package main

import (
	"errors"
	"testing"
)

func TestKeepsPlusInPassword(t *testing.T) {
	_, password, err := parseRequest("alice a+b%20c")
	if err != nil {
		t.Fatal(err)
	}
	if password != "a+b c" {
		t.Fatalf("password = %q, want %q", password, "a+b c")
	}
}

func TestRefusesChannelIDs(t *testing.T) {
	if _, _, err := parseRequest("0 alice token"); err == nil {
		t.Fatal("parsed a line with a channel ID")
	}
}

func TestListsEveryGroup(t *testing.T) {
	assertAnswer(t, verdict{outcome: accepted, groups: []string{"web", "data"}}, "OK groups_=web groups_=data")
}

// Squid keeps the previous answer's value for a key the new answer omits.
func TestSendsGroupsKeyEvenWithoutGroups(t *testing.T) {
	assertAnswer(t, verdict{outcome: accepted}, "OK groups_=")
}

func TestQuotesGroupsWithSpaces(t *testing.T) {
	assertAnswer(t, verdict{outcome: accepted, groups: []string{`Site "A" admins`}}, `OK groups_="Site \"A\" admins"`)
}

// A newline would end the answer and forge the reply to Squid's next request.
func TestRefusesGroupsThatWouldSplitTheAnswer(t *testing.T) {
	_, err := formatResponse(verdict{outcome: accepted, groups: []string{"web\nOK groups_=admin"}})
	if !errors.Is(err, errControl) {
		t.Fatalf("err = %v, want errControl", err)
	}
}

func TestGivesNoReasonToTheClient(t *testing.T) {
	assertAnswer(t, verdict{outcome: rejected, reason: "login does not match"}, "ERR")
	assertAnswer(t, verdict{outcome: broken, reason: "discovery failed"}, "BH")
}

func assertAnswer(t *testing.T, v verdict, want string) {
	t.Helper()
	got, err := formatResponse(v)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("answer = %q, want %q", got, want)
	}
}
