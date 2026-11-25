package main

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	codeOK  = "OK"
	codeERR = "ERR"
	codeBH  = "BH"
)

// groupsKey is the annotation squid.conf matches with `note groups_ <name>`.
// The trailing underscore marks it as custom: Squid 7 warns on every answer
// that carries an unknown key without one. Not "group": Squid appends that key
// across answers instead of replacing it, so removed groups would linger.
const groupsKey = "groups_"

func parseRequest(line string) (string, string, error) {
	fields := strings.Split(line, " ")
	if len(fields) != 2 {
		// No concurrency=: a channel ID would arrive as a third field.
		return "", "", fmt.Errorf("expected 2 fields, got %d (is concurrency= set in squid.conf?)", len(fields))
	}
	login, err := url.PathUnescape(fields[0])
	if err != nil {
		return "", "", fmt.Errorf("login: %w", err)
	}
	// PathUnescape, not QueryUnescape: a literal "+" in a token must not become a space.
	password, err := url.PathUnescape(fields[1])
	if err != nil {
		return "", "", fmt.Errorf("password: %w", err)
	}
	return login, password, nil
}

// The groups key is sent even when empty, not left out: Squid merges
// annotations into the cached user, so an answer without the key would keep
// the last groups.
func formatResponse(v verdict) (string, error) {
	switch v.outcome {
	case rejected:
		// No message=: it can reach the client and would describe the policy.
		return codeERR, nil
	case broken:
		return codeBH, nil
	}

	if len(v.groups) == 0 {
		return codeOK + " " + groupsKey + "=", nil
	}
	var b strings.Builder
	b.WriteString(codeOK)
	for _, g := range v.groups {
		value, err := quote(g)
		if err != nil {
			return "", fmt.Errorf("group %q: %w", g, err)
		}
		b.WriteString(" " + groupsKey + "=" + value)
	}
	return b.String(), nil
}

var errControl = errors.New("contains a control character")

// A control character is refused, not escaped: a newline would end the answer
// and start another one that Squid reads as the reply to its next request.
func quote(value string) (string, error) {
	if strings.ContainsFunc(value, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return "", errControl
	}
	if !strings.ContainsAny(value, " \t\"\\") {
		return value, nil
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(value) + `"`, nil
}
