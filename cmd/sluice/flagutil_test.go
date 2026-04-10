package main

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
	got := reorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_NameLast(t *testing.T) {
	// Already in canonical order: should be unchanged.
	fs := newTestFlagSet()
	in := []string{"--command", "https://x", "github"}
	want := []string{"--command", "https://x", "github"}
	got := reorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_NameInMiddle(t *testing.T) {
	fs := newTestFlagSet()
	in := []string{"--command", "https://x", "github", "--transport", "http"}
	want := []string{"--command", "https://x", "--transport", "http", "github"}
	got := reorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_EqualsForm(t *testing.T) {
	fs := newTestFlagSet()
	in := []string{"github", "--command=https://x", "--timeout=60"}
	want := []string{"--command=https://x", "--timeout=60", "github"}
	got := reorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_BoolFlag(t *testing.T) {
	// --verbose is a bool flag and does not consume the next arg.
	fs := newTestFlagSet()
	in := []string{"github", "--verbose", "--command", "https://x"}
	want := []string{"--verbose", "--command", "https://x", "github"}
	got := reorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_RepeatableFunc(t *testing.T) {
	fs := newTestFlagSet()
	in := []string{"github", "--header", "A=1", "--header", "B=2"}
	want := []string{"--header", "A=1", "--header", "B=2", "github"}
	got := reorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_Terminator(t *testing.T) {
	// Everything after -- is positional, even if it looks like a flag.
	fs := newTestFlagSet()
	in := []string{"--command", "X", "--", "--not-a-flag", "github"}
	want := []string{"--command", "X", "--", "--not-a-flag", "github"}
	got := reorderFlagsBeforePositional(in, fs)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestReorderFlagsBeforePositional_Empty(t *testing.T) {
	fs := newTestFlagSet()
	got := reorderFlagsBeforePositional(nil, fs)
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}
