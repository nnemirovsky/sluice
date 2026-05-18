package api

import (
	"testing"

	"github.com/nemirovsky/sluice/internal/store"
)

// TestMembersToStorePoolMembers is the Finding 7 seam: PostApiPools builds the
// 201 body from the request members (not a store read-back) so a read-back
// error can no longer turn a successful create into a misleading 500. The
// mapping must preserve order as 0-based positions (request order == failover
// order).
func TestMembersToStorePoolMembers(t *testing.T) {
	got := membersToStorePoolMembers([]string{"credA", "credB", "credC"})
	want := []store.PoolMember{
		{Credential: "credA", Position: 0},
		{Credential: "credB", Position: 1},
		{Credential: "credC", Position: 2},
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Credential != want[i].Credential || got[i].Position != want[i].Position {
			t.Fatalf("member %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// Empty members -> empty slice (not nil-panic). The handler never
	// reaches this with empty members (poolops.Create rejects them first),
	// but the helper must be total.
	if e := membersToStorePoolMembers(nil); len(e) != 0 {
		t.Fatalf("nil members -> %+v, want empty", e)
	}
}

// TestPoolCreateResponseShape_FromRequestData asserts the request-data path
// renders the same API Pool shape the read-back path would, including the
// failover strategy default poolops.Create applies for an empty strategy
// (Finding 7: the 201 body must be correct without a store read-back).
func TestPoolCreateResponseShape_FromRequestData(t *testing.T) {
	out := storePoolToAPI(store.Pool{
		Name:     "openai_pool",
		Strategy: store.PoolStrategyFailover,
		Members:  membersToStorePoolMembers([]string{"credA", "credB"}),
	})
	if out.Name != "openai_pool" {
		t.Errorf("name = %q, want openai_pool", out.Name)
	}
	if out.Strategy != store.PoolStrategyFailover {
		t.Errorf("strategy = %q, want %q", out.Strategy, store.PoolStrategyFailover)
	}
	if len(out.Members) != 2 ||
		out.Members[0].Credential != "credA" || out.Members[0].Position != 0 ||
		out.Members[1].Credential != "credB" || out.Members[1].Position != 1 {
		t.Fatalf("members = %+v, want ordered credA(0),credB(1)", out.Members)
	}
	if out.CreatedAt != nil {
		t.Errorf("CreatedAt should be nil without a read-back, got %v", *out.CreatedAt)
	}
}
