package main

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
)

// Each answer is flushed at once: Squid waits for it before sending the next line.
func serve(auth *authenticator, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	// Squid's helper line limit is 8 KiB; the default 64 KiB buffer covers it.
	w := bufio.NewWriter(out)
	for scanner.Scan() {
		fmt.Fprintln(w, respond(auth, scanner.Text()))
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func respond(auth *authenticator, line string) string {
	login, password, err := parseRequest(line)
	if err != nil {
		slog.Error("unreadable request", "error", err)
		return codeBH
	}

	v := auth.check(login, password)
	switch v.outcome {
	case accepted:
		slog.Info("accepted", "login", login, "groups", len(v.groups))
	case rejected:
		slog.Info("rejected", "login", login, "reason", v.reason)
	case broken:
		slog.Error("cannot verify", "login", login, "reason", v.reason)
	}

	answer, err := formatResponse(v)
	if err != nil {
		slog.Error("cannot encode answer", "login", login, "error", err)
		return codeBH
	}
	return answer
}
