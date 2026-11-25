package main

import (
	"strings"
	"testing"
)

func TestAnswersEachRequestLineWithOneLine(t *testing.T) {
	iss := newTestIssuer(t)
	auth := helperFor(iss)
	in := strings.Join([]string{
		"alice " + iss.valid(t, "alice", "web", "data"),
		"bob " + iss.valid(t, "alice", "web"),
		"0 alice " + iss.valid(t, "alice", "web"),
	}, "\n") + "\n"

	var out strings.Builder
	if err := serve(auth, strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	want := "OK groups_=web groups_=data\nERR\nBH\n"
	if out.String() != want {
		t.Fatalf("answers = %q, want %q", out.String(), want)
	}
}
