package proxy

import (
	"strings"
	"testing"
)

// TestFormatFailoverNotice asserts the human-facing Telegram notice wording.
// This is the new friendlier text; the audit Reason format is asserted
// separately (pool_failover_test.go etc.) and must NOT be affected.
func TestFormatFailoverNotice(t *testing.T) {
	tests := []struct {
		name     string
		ev       FailoverEvent
		want     string
		mustHave []string
	}{
		{
			name: "rate limit 429",
			ev:   FailoverEvent{Pool: "openai_pool", From: "openai_oauth_2", To: "openai_oauth", Reason: "429"},
			want: `Pool "openai_pool" failed over from "openai_oauth_2" to "openai_oauth" after rate limit (429).`,
		},
		{
			name: "quota exhausted 403",
			ev:   FailoverEvent{Pool: "p", From: "a", To: "b", Reason: "403"},
			want: `Pool "p" failed over from "a" to "b" after quota exhausted (403).`,
		},
		{
			name: "auth failure 401",
			ev:   FailoverEvent{Pool: "openai_pool", From: "openai_oauth_2", To: "openai_oauth", Reason: "401"},
			want: `Pool "openai_pool" failed over from "openai_oauth_2" to "openai_oauth" after auth failure (401).`,
		},
		{
			name: "auth failure invalid_grant",
			ev:   FailoverEvent{Pool: "p", From: "a", To: "b", Reason: "invalid_grant"},
			want: `Pool "p" failed over from "a" to "b" after auth failure (invalid_grant).`,
		},
		{
			name: "auth failure invalid_token",
			ev:   FailoverEvent{Pool: "p", From: "a", To: "b", Reason: "invalid_token"},
			want: `Pool "p" failed over from "a" to "b" after auth failure (invalid_token).`,
		},
		{
			name: "exhausted",
			ev:   FailoverEvent{Pool: "openai_pool", From: "openai_oauth_2", To: "openai_oauth_2", Reason: "429", Exhausted: true},
			want: `Pool "openai_pool" exhausted: all members are cooling down, no healthy account to fail over to (rate limit (429)).`,
		},
		{
			// Finding 5: an empty reason tag must NOT render the awkward
			// "(unknown reason)" parenthetical; the clause is dropped.
			name: "exhausted empty reason drops parenthetical",
			ev:   FailoverEvent{Pool: "openai_pool", From: "a", To: "a", Reason: "", Exhausted: true},
			want: `Pool "openai_pool" exhausted: all members are cooling down, no healthy account to fail over to.`,
		},
		{
			// Finding 5: normal failover with an empty reason tag drops the
			// "after unknown reason" clause entirely.
			name: "normal failover empty reason drops clause",
			ev:   FailoverEvent{Pool: "p", From: "a", To: "b", Reason: ""},
			want: `Pool "p" failed over from "a" to "b".`,
		},
		{
			// Finding 2: an unknown tag must read naturally after "after"
			// (no redundant "failed over ... after failover (teapot)").
			name: "unknown tag reads naturally after the after-clause",
			ev:   FailoverEvent{Pool: "p", From: "a", To: "b", Reason: "teapot"},
			want: `Pool "p" failed over from "a" to "b" after unknown reason (teapot).`,
		},
		{
			// Finding 2: an unknown tag in the exhausted message also reads
			// naturally and still surfaces the raw tag.
			name:     "unknown tag in exhausted message reads naturally",
			ev:       FailoverEvent{Pool: "p", From: "a", To: "a", Reason: "teapot", Exhausted: true},
			want:     `Pool "p" exhausted: all members are cooling down, no healthy account to fail over to (unknown reason (teapot)).`,
			mustHave: []string{"teapot"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatFailoverNotice(tt.ev)
			if tt.want != "" && got != tt.want {
				t.Fatalf("FormatFailoverNotice() =\n  %q\nwant\n  %q", got, tt.want)
			}
			for _, sub := range tt.mustHave {
				if !strings.Contains(got, sub) {
					t.Fatalf("FormatFailoverNotice() = %q, missing %q", got, sub)
				}
			}
			// Plain-text contract: no markdown/HTML the notice path can't
			// render. (Underscores/asterisks are legitimate in pool and
			// credential names — invalid_grant, openai_pool — and Notify
			// sends no parse mode, so they render literally and are safe.)
			for _, bad := range []string{"`", "<b>", "<code>", "</a>", "**"} {
				if strings.Contains(got, bad) {
					t.Fatalf("FormatFailoverNotice() = %q, contains non-plain-text %q", got, bad)
				}
			}
			if strings.Contains(got, "\n") {
				t.Fatalf("FormatFailoverNotice() = %q, must be a single line", got)
			}
		})
	}
}

// TestHumanizeFailoverReason covers every reason tag form produced by
// failoverReasonTag / classifyFailover so none falls through unlabeled. The
// empty-tag case is intentionally absent: it is handled by
// FormatFailoverNotice (the sole caller short-circuits an empty reason and
// drops the clause), asserted by TestFormatFailoverNotice's empty-reason
// cases, so humanizeFailoverReason has no reachable "" branch.
func TestHumanizeFailoverReason(t *testing.T) {
	cases := map[string]string{
		"429":           "rate limit (429)",
		"403":           "quota exhausted (403)",
		"401":           "auth failure (401)",
		"invalid_grant": "auth failure (invalid_grant)",
		"invalid_token": "auth failure (invalid_token)",
		"weird":         "unknown reason (weird)",
	}
	for tag, want := range cases {
		if got := humanizeFailoverReason(tag); got != want {
			t.Fatalf("humanizeFailoverReason(%q) = %q, want %q", tag, got, want)
		}
	}
}
