package flagutil

import (
	"flag"
	"reflect"
	"testing"
)

func newTestFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("command", "", "")
	fs.String("transport", "stdio", "")
	fs.Int("timeout", 120, "")
	fs.Bool("verbose", false, "")
	fs.Func("header", "", func(string) error { return nil })
	return fs
}

func TestReorderFlagsBeforePositional_NameFirst(t *testing.T) {
	fs := newTestFlagSet()
	in := []string{"github", "--command", "https://x", "--transport", "http"}
	want := []string{"--command", "https://x", "--transport", "http", "github"}
	got := ReorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_NameLast(t *testing.T) {
	fs := newTestFlagSet()
	in := []string{"--command", "https://x", "github"}
	want := []string{"--command", "https://x", "github"}
	got := ReorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_NameInMiddle(t *testing.T) {
	fs := newTestFlagSet()
	in := []string{"--command", "https://x", "github", "--transport", "http"}
	want := []string{"--command", "https://x", "--transport", "http", "github"}
	got := ReorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_EqualsForm(t *testing.T) {
	fs := newTestFlagSet()
	in := []string{"github", "--command=https://x", "--timeout=60"}
	want := []string{"--command=https://x", "--timeout=60", "github"}
	got := ReorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_BoolFlag(t *testing.T) {
	fs := newTestFlagSet()
	in := []string{"github", "--verbose", "--command", "https://x"}
	want := []string{"--verbose", "--command", "https://x", "github"}
	got := ReorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_RepeatableFunc(t *testing.T) {
	fs := newTestFlagSet()
	in := []string{"github", "--header", "A=1", "--header", "B=2"}
	want := []string{"--header", "A=1", "--header", "B=2", "github"}
	got := ReorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_Terminator(t *testing.T) {
	fs := newTestFlagSet()
	in := []string{"--command", "X", "--", "--not-a-flag", "github"}
	want := []string{"--command", "X", "--", "--not-a-flag", "github"}
	got := ReorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_SingleDashFlag(t *testing.T) {
	// Single-dash short flags (e.g. "-command") should be treated as flags,
	// matching Go's stdlib flag parser which accepts both "-foo" and "--foo".
	fs := newTestFlagSet()
	in := []string{"github", "-command", "https://x"}
	want := []string{"-command", "https://x", "github"}
	got := ReorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_BareDash(t *testing.T) {
	// A bare "-" (often stdin) is positional, not a flag.
	fs := newTestFlagSet()
	in := []string{"-", "--command", "X"}
	want := []string{"--command", "X", "-"}
	got := ReorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_Empty(t *testing.T) {
	fs := newTestFlagSet()
	got := ReorderFlagsBeforePositional(nil, fs)
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

// TestReorderFlagsBeforePositional_UnknownFlag exercises the isValueFlag
// f == nil branch. When the reorderer encounters a flag that is not
// registered on the FlagSet (e.g. a typo like --cmmand or an arg that
// happens to look like a flag), it conservatively assumes the flag
// consumes the next arg. This keeps the original token adjacency so that
// fs.Parse can later produce a precise "flag provided but not defined"
// error, rather than mis-splitting the stream and surfacing a cryptic
// positional-arg error instead.
func TestReorderFlagsBeforePositional_UnknownFlag(t *testing.T) {
	fs := newTestFlagSet()
	in := []string{"github", "--unknown", "val", "--command", "https://x"}
	want := []string{"--unknown", "val", "--command", "https://x", "github"}
	got := ReorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
