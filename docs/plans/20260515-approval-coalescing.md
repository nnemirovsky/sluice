# Coalesce Duplicate Approval Prompts (broker-level dedup)

## Overview

When the agent fires many requests to the same target while the **first**
approval is still pending, the broker creates one independent waiter + one
Telegram message **per request** — the wall of identical "Hermes wants to
connect to: HTTPS cas-server.xethub.hf.co:443 …" prompts the user reported,
each demanding its own tap, even though "Always Allow" persists a rule keyed
only by `destination:port`.

Fix: **coalesce pending approvals by their persistence-equivalent target**
(`dest:port`). The first request to a target opens one prompt; concurrent
requests to the same target while it is pending **attach to that same pending
approval**. On resolve, every attached waiter gets the same response. This
generalises the QUIC-only buffering pattern in `internal/proxy/server.go` to
the channel-agnostic broker so HTTP/HTTPS / gRPC / WS *and connection-level
SSH / IMAP / SMTP* (which all share one broker call site) get dedup.

**Scoping decision (from review):** ship the actual fix — broker coalescing —
in **Phase 1**, with the final coalesced count folded into the *existing*
resolve/cancel message edit (zero extra Telegram API calls, zero throttle
logic). The live mid-burst "+N pending" counter, whose only complexity is Bot
API flood-control realism, is **Phase 2 (optional)** and orthogonal to fixing
the prompt wall.

## Context

Verified against the working tree on `main` (tip `20cc367`):

- **Exactly three `broker.Request` call sites exist** (grep-confirmed):
  1. `internal/proxy/request_policy.go:299` (`resolveAsk`) — the **sole** Ask path for per-request HTTP/gRPC/WS **and** connection-level SSH/IMAP/SMTP. Connection-level Ask is deferred at `internal/proxy/server.go:376-393` and resolved through this same `CheckAndConsume → resolveAsk → broker.Request`. There is **no separate SSH/IMAP/SMTP call site.**
  2. `internal/proxy/server.go:2477` — QUIC (already has its own packet-buffering dedup; **left untouched**).
  3. `internal/mcp/gateway.go:228` — MCP tool calls, keyed by tool name + args, `port 0`. A `dest:port` dedup key would wrongly collapse semantically distinct tool calls (different `ToolArgs`, arg-sensitive ContentInspector/exec rules). **MCP must opt out.**
- `internal/channel/broker.go`: `Broker{waiters map[string]waiter}` `:32`; ids `req_N` auto-increment `:161`, **not keyed by target**; `broadcast` to all channels `:226`/`:277-289`; blocking `select` `:232-271`; primary `ch` is **buffered cap 1** `:162`. `Resolve(id,resp)` `:344-358` first-wins per id, deletes waiter under lock, releases lock, *then* `w.ch <- resp` + `cancelOnChannels`.
- Timeout path `:248-271` does `delete(b.waiters,id)` + `b.timedOut[id]=now`. A coalesced sub has **no id of its own**, so it must use a *different* select arm (detach-from-subs only) — the existing arm would tear down the shared primary waiter.
- `persistApprovalRule` `internal/proxy/server.go:506-530` writes `store.AddRule(verdict, RuleOpts{Destination:dest, Ports:[]int{port}, Source:"approval"})` — **dest:port only, no method/path**, guarded by `reloadMu`. `store.AddRule` is the only entry point; **there is no existing "rule exists?" query** — adding one is a plain SELECT, no migration.
- Telegram `internal/telegram/approval.go`: `msgMap sync.Map` of `approvalMsg{messageID, req}` `:163`; inline keyboard built `:141-150`; resolve edit `:332-353` and cancel edit `:181-199` both use `NewEditMessageText` **without** re-attaching markup (intentional — they remove the keyboard). Library is `go-telegram-bot-api`; **`EditMessageTextAndMarkup` does not exist** — keyboard preservation needs an explicit `tgbotapi.EditMessageTextConfig` with `.ReplyMarkup` set to the rebuilt inline keyboard.
- HTTP per-request already bypasses the 5/min limiter via `WithBypassRateLimit` (`request_policy.go:268`, `broker.go:152`), so coalescing won't interact with it.

## Development Approach

- **Testing approach**: Regular (code first, then tests). Tests enumerated as explicit per-task items.
- gofumpt before commit (`feedback_gofumpt`); PR to `main` (`feedback_pr_workflow`).
- Two phases. Phase 1 is the complete fix and is shippable alone.

## Testing Strategy

- **Unit (broker)**: N concurrent same-`dest:port` `Request` → exactly **one** `broadcast`; one `Resolve` fans to **all N**; late arrival between resolve and index-clear does **not** attach to a dead waiter (drives the exact interleave); a **sub whose caller timed out and detached does not block `Resolve` fan-out**; deny/timeout/shutdown fan to all subs; different `dest:port` not coalesced; `WithNoCoalesce` requests never coalesce; first-wins across channels still works on the primary id.
- **Unit (persist)**: M coalesced `ResponseAlwaysAllow` → rule inserted **once** (new `HasApprovalRule` SELECT under `reloadMu`); **MCP calls with different `ToolArgs` are NOT coalesced.**
- **Unit (Telegram)**: final count folded into the existing resolve/cancel edit (no extra Send); Phase 2 only — live counter edit preserves keyboard and honors `retry_after`.
- **E2e** (`e2e`): burst of HTTP requests to one Ask destination through the proxy with the webhook channel; assert one approval delivered, one response fans to all, all proceed. Confirm the webhook/HTTP channel either implements `CoalesceNotifier` or is an explicit no-op so the assertion is meaningful.

## Phase 1 — Broker coalescing + final-count-on-resolve (the fix)

### Task 1: Broker coalescing core

**Files:** Modify `internal/channel/broker.go`; Modify `internal/channel/broker_test.go`

- Add to `Broker`: `dedupIndex map[string]string` (`dedupKey → primary reqID`); extend `waiter` with `subs []chan Response`, `count int` (starts 1), and `dedupKey string`.
- Add `WithNoCoalesce()` request option (escape hatch).
- `Request`: compute `dedupKey := dest + ":" + strconv.Itoa(port)` (proto-agnostic — matches the proto-agnostic persisted rule). If `WithNoCoalesce` set, skip all dedup logic.
- Under `b.mu`: if `dedupIndex[dedupKey]` exists and that primary waiter is still in `waiters` → create a **buffered (cap 1)** response chan, append to `waiters[primary].subs`, `count++`, capture primary id + count; release lock; (Phase 2 only: notify channels of new count). Block on the sub chan using a **sub-specific select** arm: `case resp := <-subCh` (return it) / `case <-deadline.C` (under `b.mu`: remove this chan from `waiters[primary].subs` if still present, then return timeout deny — **no `waiters` delete, no `timedOut` entry**, must not tear down the shared waiter) / `case <-b.done` (drain subCh non-blocking then deny).
- Else: today's behavior — new id, register waiter, set `dedupIndex[dedupKey]=id`, record `dedupKey` on the waiter, `broadcast`.
- `Resolve(id,resp)`: under `b.mu` look up waiter, **snapshot the whole waiter (including the `subs` slice)**, delete `b.waiters[id]` **and** `delete(b.dedupIndex, w.dedupKey)` in the *same locked section* (this is what closes the late-attach race), release lock, then fan `resp` to `w.ch` and every chan in the snapshot `subs` (all buffered cap 1 so a send to a detached/timed-out sub never blocks), then `cancelOnChannels(id)`. First-wins preserved: only the call that finds the waiter present wins.
- Timeout/`done`/shutdown of the **primary**: fan the terminal response to all snapshot subs and clear `dedupIndex` under the same lock discipline.
- write tests: concurrent dedup → one broadcast; fan-out to all N; late-attach interleave (no attach to dead waiter); sub-timeout-detach does not block fan-out; deny/timeout/shutdown fan-out; distinct dest:port; `WithNoCoalesce`; cross-channel first-wins.
- run `go test ./internal/channel/...` — must pass before Task 2.

### Task 2: Persist-once (idempotent approval rule)

**Files:** Modify `internal/store/store.go`; Modify `internal/proxy/server.go`; Modify `internal/store/store_test.go`

- Add `Store.HasApprovalRule(verdict, dest string, port int) (bool, error)` — plain SELECT against `rules` where `source='approval'` AND verdict/destination/port match. **No migration** (read-only query).
- In `persistApprovalRule` (`server.go:506`), under the existing `reloadMu`, call `HasApprovalRule` first and skip `AddRule` + engine recompile if present (M coalesced callers serialize on `reloadMu`; first inserts, rest no-op). This is the chosen design over "only primary persists" because it needs no broker→persist signaling and is robustly idempotent under concurrent resolve fan-out. (Scope note: this is *not* a vehicle for fixing any pre-existing manual double-tap dup-row behavior — that is out of scope and not a design driver.)
- write tests: M concurrent persists → exactly one row; existing single-persist path unchanged.
- run `go test ./internal/store/... ./internal/proxy/...` — must pass before Task 3.

### Task 3: Route call sites; MCP opt-out

**Files:** Modify `internal/mcp/gateway.go`; audit `internal/proxy/request_policy.go`, `internal/proxy/server.go`

- `request_policy.go:299` (HTTP/gRPC/WS + connection-level SSH/IMAP/SMTP): coalesce **uniformly**. Rationale: an SSH/IMAP burst to one `dest:port` persists the *same* single `dest:port` rule as HTTP — the plan's own "persistence granularity = dedup granularity" thesis applies identically; no per-protocol special-casing, no `checkContext` plumbing.
- `mcp/gateway.go:228`: pass `WithNoCoalesce()` — distinct `ToolArgs` are semantically distinct and arg-sensitive (ContentInspector/exec). This is the call site that genuinely needs the escape hatch.
- QUIC (`server.go:2477`): untouched (its own buffering remains).
- write tests: MCP calls with differing `ToolArgs` produce distinct prompts (not coalesced); SSH-style connection-level Ask to same dest:port coalesces.
- run `go test ./...` — must pass before Task 4.

### Task 4: Final count on the existing resolve/cancel edit

**Files:** Modify `internal/telegram/approval.go`; Modify `internal/channel/broker.go` (expose final `count` on resolve); Modify `internal/telegram/approval_test.go`

- Broker passes the final coalesced `count` to channels on cancel/resolve (extend the existing cancel/resolve notification path; no new Telegram Send).
- Telegram resolve edit (`:332-353`) / cancel edit (`:181-199`): when `count > 1`, render e.g. "Always allowed — applied to N requests at HH:MM:SS". **Zero extra API calls** — folded into the one edit that already happens.
- write tests: count rendered correctly for count==1 and count>1; no additional `Send` beyond the existing single edit.
- run `go test ./internal/telegram/...` — must pass.

### Task 5: Verify acceptance + docs

- verify the prompt-wall scenario: burst → one prompt → one tap dismisses all (e2e).
- run full suite `go test ./... -timeout 30s`; run e2e `go test -tags=e2e ./e2e/ -count=1 -timeout=300s`.
- update CLAUDE.md "Channel/approval abstraction" + "QUIC broker dedup" notes to mention broker-level coalescing.
- move plan to `docs/plans/completed/`.

## Phase 2 (optional) — Live mid-burst counter

Only if the live "+N more pending" indicator is wanted on top of Phase 1.

**Files:** Modify `internal/channel` (new `CoalesceNotifier interface { ApprovalCoalesced(id string, count int) }`); Modify `internal/telegram/approval.go`

- Broker, on attaching a sub, best-effort calls `ch.ApprovalCoalesced(primaryID, count)` for channels implementing the interface (panic-recover like `broadcast`).
- `TelegramChannel.ApprovalCoalesced`: edit the stored message appending `<i>+%d more identical request(s) to this target pending</i>`, **preserving the keyboard** via an explicit `tgbotapi.EditMessageTextConfig` with `.ReplyMarkup` = pointer to the inline keyboard rebuilt from `req.ID` (the `:141-150` shape) — `EditMessageTextAndMarkup` does not exist in the library.
- Throttle: ≥800ms between edits per message, coalesce intermediate bumps; **on HTTP 429 honor `retry_after`** and drop intermediate edits (the final count still rides Phase 1's resolve edit, so a dropped mid-burst edit loses nothing material).
- Tests: keyboard preserved across the edit; `retry_after` honored (no tight-loop retry); final count still correct via Phase 1 path.

## Out of scope

Cross-port coalescing of one host; wildcard "similar resource" grouping (persisted rule is exact host:port — dedup must match); aggregate burst audit metric (per-request audit already covers it); fixing any pre-existing manual double-tap dup-row behavior.

## Risks / decisions

- **Late-attach race** (arrival between resolve and dedupIndex clear): closed by deleting `waiters[id]` and `dedupIndex[key]` in the *same* locked section and fanning out to a subs **snapshot** taken under that lock; sends happen after unlock to buffered (cap 1) chans. Explicit interleave unit test (Task 1).
- **Sub timeout vs shared waiter**: subs use a dedicated select arm that detaches only themselves; never delete the primary waiter or write `timedOut`. Buffered sub chans guarantee `Resolve` fan-out never blocks on a departed sub.
- **Call-site topology**: only three `broker.Request` sites; SSH/IMAP/SMTP share `request_policy.go:299` with HTTP (coalesce uniformly); MCP `gateway.go:228` opts out; QUIC untouched. (Original plan's "SSH needs WithNoCoalesce" was based on a non-existent call site — corrected.)
- **Behavioral change**: an operator who wanted to deny individual requests now sees one prompt for the burst — matches persisted-rule granularity (one rule covers them all) and the user's explicit request; intended.
- **Telegram realism**: Phase 1 adds **zero** new API calls (final count rides the existing edit). Flood-control risk is entirely confined to optional Phase 2, which handles `retry_after`.
