package proxy

import (
	"testing"

	uuid "github.com/satori/go.uuid"
)

// flowInjectedSize returns the current number of live flow-attribution
// entries. Tests are in package proxy so the unexported map is directly
// reachable; the read is taken under the same mutex Tag/Peek/Delete use.
func flowInjectedSize(m *flowInjectedMember) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

// TestFlowInjectedTagFreedAfterResponse is the Finding 1 regression.
//
// Round-12 made poolForResponse's API-host branch use a NON-consuming Peek,
// so a COMPLETED pooled request's flow tag was never deleted until the 5-min
// flowAttrTTL sweep. Tag opportunistically scans the WHOLE map on every new
// pooled request, so sustained pooled traffic accumulated every completed
// flow for the TTL window: each new Tag became O(n) and the map grew
// unboundedly within the TTL.
//
// The fix deletes the per-flow tag at the end of the buffered Response
// handler (after handlePoolFailover -> poolForResponse has used it via Peek
// AND/OR Recover). This test drives N completed pooled API-host requests
// through Response and asserts:
//
//   - the flowInjected map does NOT retain all N entries afterwards (it is
//     bounded near zero, not ~N) — fails before the fix (map == N), passes
//     after (map == 0);
//   - attribution is still correct DURING each request's own Response: the
//     request whose 429 is processed cools its OWN injected member;
//   - the TTL backstop still works: a tagged flow whose Response never fires
//     (streamed/abandoned) is retained for the caller to clean up via the
//     TTL + Tag sweep, i.e. Delete did not over-reach and wipe live tags.
func TestFlowInjectedTagFreedAfterResponse(t *testing.T) {
	addon, _, prPtr := setupPoolAddon(t, "memA", "memB")
	client := setupAddonConn(addon, "auth.example.com:443")
	pr := prPtr.Load()

	if got, _ := pr.ResolveActive("codex_pool"); got != "memA" {
		t.Fatalf("pre-condition active = %q, want memA", got)
	}

	const n = 50
	for i := 0; i < n; i++ {
		// A completed pooled API-host request that succeeded (2xx, no
		// failover). Production tags the injected member post-swap; mirror
		// that. memA is the active member for all of them.
		f := newPoolRespFlow(client, 200, []byte(`{"ok":true}`))
		addon.flowInjected.Tag(f.Id, "memA")
		addon.Response(f)
	}

	// The crux: after N completed Responses the map must NOT still hold all
	// N tags. Before the fix every Peek-only completion left its entry
	// behind, so size == N. After the fix each Response frees its own tag,
	// so size is 0.
	if sz := flowInjectedSize(addon.flowInjected); sz > 1 {
		t.Fatalf("flowInjected retained %d/%d completed-request tags after their "+
			"Responses — Finding 1: Peek-only API-host path never frees tags, "+
			"so the map grows unboundedly within flowAttrTTL and Tag is O(n)", sz, n)
	}

	// Attribution must still be correct DURING a request's own Response.
	// Two concurrent requests both backed by memA. req1's 429 cools memA
	// (pool switches to memB); req2's 429 must still be attributed to memA
	// (its OWN injected member, recovered by flow id) and NOT to memB
	// (response-time active). Then both tags must be freed.
	req1 := newPoolRespFlow(client, 429, []byte(`{"error":"rate_limited"}`))
	req2 := newPoolRespFlow(client, 429, []byte(`{"error":"rate_limited"}`))
	addon.flowInjected.Tag(req1.Id, "memA")
	addon.flowInjected.Tag(req2.Id, "memA")

	addon.Response(req1)
	if _, cooling := pr.CooldownUntil("memA"); !cooling {
		t.Fatal("memA must be cooling after req1's 429")
	}
	if got, _ := pr.ResolveActive("codex_pool"); got != "memB" {
		t.Fatalf("after req1 failover active = %q, want memB", got)
	}

	addon.Response(req2)
	if _, cooling := pr.CooldownUntil("memB"); cooling {
		t.Fatal("memB was cooled by req2's 429 — attribution must use req2's " +
			"OWN injected member (memA), not response-time active (Finding 1)")
	}

	if sz := flowInjectedSize(addon.flowInjected); sz != 0 {
		t.Fatalf("flowInjected size = %d after all Responses, want 0 "+
			"(every completed flow's tag must be freed)", sz)
	}

	// TTL backstop: a tag for a flow whose Response NEVER fires (streamed /
	// abandoned) must survive — Delete must not have over-reached. The tag
	// is bounded only by flowAttrTTL + the opportunistic sweep in Tag.
	abandoned := uuid.NewV4()
	addon.flowInjected.Tag(abandoned, "memA")
	if m, ok := addon.flowInjected.Peek(abandoned); !ok || m != "memA" {
		t.Fatalf("abandoned-flow tag not retained as TTL backstop; got %q ok=%v", m, ok)
	}
	if sz := flowInjectedSize(addon.flowInjected); sz != 1 {
		t.Fatalf("flowInjected size = %d, want exactly 1 (only the abandoned "+
			"flow's TTL-backstopped tag remains)", sz)
	}
}

// TestFlowInjectedDeleteIsIdempotent guards the end-of-Response delete: the
// token-endpoint failover path already consumes the tag via a single-use
// Recover, so the subsequent end-of-Response Delete must be a safe no-op
// (not panic, not corrupt the map) and must not disturb other flows' tags.
func TestFlowInjectedDeleteIsIdempotent(t *testing.T) {
	m := newFlowInjectedMember()
	id1 := uuid.NewV4()
	id2 := uuid.NewV4()
	m.Tag(id1, "memA")
	m.Tag(id2, "memB")

	// First delete frees id1.
	m.Delete(id1)
	if _, ok := m.Peek(id1); ok {
		t.Fatal("id1 tag must be gone after Delete")
	}
	// Second delete of the same id is a no-op.
	m.Delete(id1)
	// uuid.Nil delete is a no-op.
	m.Delete(uuid.Nil)
	// id2 is untouched throughout.
	if got, ok := m.Peek(id2); !ok || got != "memB" {
		t.Fatalf("id2 tag disturbed by unrelated Delete calls; got %q ok=%v", got, ok)
	}
	if sz := flowInjectedSize(m); sz != 1 {
		t.Fatalf("size = %d, want 1 (only id2 remains)", sz)
	}
}
