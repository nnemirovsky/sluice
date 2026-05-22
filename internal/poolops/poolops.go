// Package poolops holds the channel-agnostic credential-pool operations
// (create / list / status / rotate / remove). CLI, the REST API, and the
// Telegram bot are all thin adapters over this package so the three
// management surfaces cannot drift.
//
// The epoch-guarded rotate write and the ResolveActive-based status
// derivation live here exactly once. This is the fix for the historical
// parity gap where the logic was written inline in cmd/sluice and could not
// be reused by other channels.
package poolops

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nemirovsky/sluice/internal/store"
	"github.com/nemirovsky/sluice/internal/vault"
)

// Store is the subset of *store.Store the pool operations need. Keeping it an
// interface lets each channel pass its own already-open store and lets the
// tests substitute a fake.
type Store interface {
	CreatePoolWithMembers(name, strategy string, members []string) error
	GetPool(name string) (*store.Pool, error)
	ListPools() ([]store.Pool, error)
	RemovePoolIfUnreferenced(name string) (bool, error)
	ListCredentialHealth() ([]store.CredentialHealth, error)
	SetCredentialHealthIfPoolMemberEpoch(credential, pool string, epoch int64, status string, cooldownUntil time.Time, reason string) (bool, error)
	SetPoolAuthResetTarget(name, target string) error
}

// ErrNoMembers is returned by Create when the member list is empty.
var ErrNoMembers = errors.New("at least one member credential is required")

// PoolNotFoundError is returned by Status/Rotate/Remove when the named pool
// does not exist. Channels map this to a 404 / "not found" message.
type PoolNotFoundError struct {
	Name string
}

func (e *PoolNotFoundError) Error() string {
	return fmt.Sprintf("pool %q not found", e.Name)
}

// RotateRaceError is returned by Rotate when a concurrent pool/member
// removal or cross-pool re-add invalidated the snapshot the rotate was
// computed from, so nothing was persisted. The operator should re-check the
// pool and retry.
type RotateRaceError struct {
	Pool   string
	Member string
	Epoch  int64
}

func (e *RotateRaceError) Error() string {
	// Channel-neutral: poolops is shared by CLI, REST and Telegram, so the
	// message states the condition without prescribing a CLI command. Each
	// channel adds its own remediation hint at its adapter layer.
	return fmt.Sprintf("pool %q rotate raced a concurrent pool/member removal or re-add: %q is no longer a live member of pool %q at the snapshotted epoch %d, so nothing was persisted",
		e.Pool, e.Member, e.Pool, e.Epoch)
}

// MemberStatus is one member's view in a StatusResult.
type MemberStatus struct {
	Credential        string
	Position          int
	Active            bool
	State             string // "healthy", "cooldown", "healthy (cooldown expired)"
	CooldownUntil     time.Time
	LastFailureReason string
}

// StatusResult is the channel-agnostic pool status. Channels render it
// however suits their surface (CLI text, JSON, Telegram).
type StatusResult struct {
	Name     string
	Strategy string
	Active   string
	// AuthResetTarget is the per-pool agent auth-reset target (empty = none).
	AuthResetTarget string
	Members         []MemberStatus
}

// RotateResult is the outcome of a successful Rotate.
type RotateResult struct {
	Pool        string
	From        string
	To          string
	ParkedUntil time.Time
}

// ParseMembers splits a comma-separated member list into a trimmed slice,
// rejecting empty entries. Shared by every channel that accepts the list as a
// single string (CLI --members, Telegram args, REST CSV fallback).
func ParseMembers(membersStr string) ([]string, error) {
	if strings.TrimSpace(membersStr) == "" {
		return nil, ErrNoMembers
	}
	var members []string
	for _, m := range strings.Split(membersStr, ",") {
		m = strings.TrimSpace(m)
		if m == "" {
			return nil, fmt.Errorf("empty credential name in members list")
		}
		members = append(members, m)
	}
	return members, nil
}

// ErrInvalidAuthResetTarget is returned when a non-empty auth-reset target
// contains a NUL byte or newline. The target is consumed as argv (never
// shell-interpolated), so this is a minimal structural guard, not a
// shell-metachar check; channels that exec the target apply any stricter
// allowlist at exec time.
var ErrInvalidAuthResetTarget = errors.New("invalid auth_reset_target: must not contain NUL or newline characters")

// validateAuthResetTarget rejects a non-empty target containing a NUL byte or
// a newline. An empty target ("") is always valid and means "clear / no
// reset", so callers normalize the clear sentinel before validating.
func validateAuthResetTarget(target string) error {
	if target == "" {
		return nil
	}
	if strings.ContainsAny(target, "\x00\n\r") {
		return ErrInvalidAuthResetTarget
	}
	return nil
}

// Create creates a pool with the given ordered members. An empty strategy
// defaults to the only supported strategy (failover). Sentinel errors from
// the store (namespace collision, static member, unknown member) propagate
// unchanged so channels can map them.
func Create(s Store, name, strategy string, members []string) error {
	return CreateWithAuthResetTarget(s, name, strategy, members, "")
}

// CreateWithAuthResetTarget is Create plus an optional per-pool
// auth_reset_target (empty = no reset). The target is set in a follow-up
// SetPoolAuthResetTarget call after the pool exists; channels that don't
// accept a target call Create. Used by every channel's create adapter so the
// create-with-target path has a single source of truth.
func CreateWithAuthResetTarget(s Store, name, strategy string, members []string, authResetTarget string) error {
	if strategy == "" {
		strategy = store.PoolStrategyFailover
	}
	if len(members) == 0 {
		return ErrNoMembers
	}
	if err := validateAuthResetTarget(authResetTarget); err != nil {
		return err
	}
	if err := s.CreatePoolWithMembers(name, strategy, members); err != nil {
		return err
	}
	if authResetTarget != "" {
		if err := s.SetPoolAuthResetTarget(name, authResetTarget); err != nil {
			return err
		}
	}
	return nil
}

// SetAuthResetTarget sets (target != "") or clears (target == "") the
// per-pool auth_reset_target. Channels normalize their clear sentinel (CLI /
// Telegram use a single "-") to "" before calling. A missing pool surfaces as
// the store's "does not exist" error; channels may also wrap it as a
// *PoolNotFoundError by checking existence first.
func SetAuthResetTarget(s Store, name, target string) error {
	if err := validateAuthResetTarget(target); err != nil {
		return err
	}
	if _, err := mustExist(s, name); err != nil {
		return err
	}
	return s.SetPoolAuthResetTarget(name, target)
}

// mustExist returns the pool or a *PoolNotFoundError, so channels get the same
// typed not-found error from SetAuthResetTarget that Status/Rotate/Remove
// already return.
func mustExist(s Store, name string) (*store.Pool, error) {
	p, err := s.GetPool(name)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, &PoolNotFoundError{Name: name}
	}
	return p, nil
}

// List returns every configured pool, ordered as the store returns them.
func List(s Store) ([]store.Pool, error) {
	return s.ListPools()
}

// Status derives the active member with the exact same selection logic the
// proxy uses at injection time (vault.NewPoolResolver.ResolveActive) so the
// reported status never disagrees with what would actually be injected.
func Status(s Store, name string) (*StatusResult, error) {
	p, err := s.GetPool(name)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, &PoolNotFoundError{Name: name}
	}
	healthRows, err := s.ListCredentialHealth()
	if err != nil {
		return nil, err
	}

	resolver := vault.NewPoolResolver([]store.Pool{*p}, healthRows)
	active, _ := resolver.ResolveActive(name)

	healthByCred := make(map[string]store.CredentialHealth, len(healthRows))
	for _, h := range healthRows {
		healthByCred[h.Credential] = h
	}

	now := time.Now()
	res := &StatusResult{Name: p.Name, Strategy: p.Strategy, Active: active, AuthResetTarget: p.AuthResetTarget}
	for _, m := range p.Members {
		ms := MemberStatus{
			Credential: m.Credential,
			Position:   m.Position,
			Active:     m.Credential == active,
			State:      "healthy",
		}
		if h, ok := healthByCred[m.Credential]; ok && h.Status == "cooldown" && !h.CooldownUntil.IsZero() {
			ms.CooldownUntil = h.CooldownUntil
			ms.LastFailureReason = h.LastFailureReason
			if h.CooldownUntil.After(now) {
				ms.State = "cooldown"
			} else {
				ms.State = "healthy (cooldown expired)"
			}
		}
		res.Members = append(res.Members, ms)
	}
	return res, nil
}

// Rotate is the operator override: park the current active member so the
// next member in position order becomes active. The cooldown lapses on its
// own (lazy recovery, same as auto-failover), so a rotated-away member
// rejoins the rotation once its cooldown expires.
//
// The write is the pool+epoch scoped guarded write, NOT the unconditional
// SetCredentialHealth and NOT a name-only guard. `active` is resolved from a
// snapshot; another process could remove this pool (or this member from it)
// AND re-add the same name into a DIFFERENT pool between that snapshot and
// this write. Gating on exactly (active, this pool, that epoch) makes a
// raced removal/re-add a no-op (wrote=false) instead of silently parking an
// unrelated pool's member; the caller gets a RotateRaceError.
func Rotate(s Store, name string) (*RotateResult, error) {
	p, err := s.GetPool(name)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, &PoolNotFoundError{Name: name}
	}
	healthRows, err := s.ListCredentialHealth()
	if err != nil {
		return nil, err
	}
	resolver := vault.NewPoolResolver([]store.Pool{*p}, healthRows)
	active, ok := resolver.ResolveActive(name)
	if !ok || active == "" {
		return nil, fmt.Errorf("pool %q has no resolvable member to rotate away from", name)
	}

	var rotateEpoch int64 = -1
	for _, m := range p.Members {
		if m.Credential == active {
			rotateEpoch = m.Epoch
			break
		}
	}
	if rotateEpoch < 0 {
		return nil, fmt.Errorf("pool %q rotate: resolved active member %q is not in the pool snapshot (membership changed under the rotate)", name, active)
	}
	until := time.Now().Add(vault.AuthFailCooldown)
	wrote, err := s.SetCredentialHealthIfPoolMemberEpoch(active, name, rotateEpoch, "cooldown", until, vault.ManualRotateReason)
	if err != nil {
		return nil, err
	}
	if !wrote {
		return nil, &RotateRaceError{Pool: name, Member: active, Epoch: rotateEpoch}
	}

	// Recompute the new active member for operator feedback.
	healthRows, err = s.ListCredentialHealth()
	if err != nil {
		return nil, err
	}
	resolver = vault.NewPoolResolver([]store.Pool{*p}, healthRows)
	next, _ := resolver.ResolveActive(name)
	return &RotateResult{Pool: name, From: active, To: next, ParkedUntil: until}, nil
}

// Remove deletes the pool, refusing (with a *store.PoolReferencedError) while
// any binding still references it by name. The store method folds the
// reference check and the delete into one transaction; this function only
// surfaces the typed errors. Returns a *PoolNotFoundError if the pool does
// not exist.
func Remove(s Store, name string) error {
	removed, err := s.RemovePoolIfUnreferenced(name)
	if err != nil {
		return err
	}
	if !removed {
		return &PoolNotFoundError{Name: name}
	}
	return nil
}
