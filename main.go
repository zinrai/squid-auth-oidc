// squid-auth-oidc is a Squid Basic authentication helper that accepts an OIDC
// ID token as the proxy password.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// fetchTimeout bounds discovery and key set requests, so a hung issuer turns
// into BH instead of a helper Squid waits on forever.
const fetchTimeout = 10 * time.Second

type config struct {
	issuer        string
	clientID      string
	usernameClaim string
	showVersion   bool
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, "squid-auth-oidc:", err)
		os.Exit(2)
	}
	if cfg.showVersion {
		printVersion()
		return
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	auth := newAuthenticator(cfg, http.DefaultTransport)
	if err := serve(auth, os.Stdin, os.Stdout); err != nil {
		slog.Error("reading from Squid", "error", err)
		os.Exit(1)
	}
}

func parseFlags() (config, error) {
	var cfg config
	flag.StringVar(&cfg.issuer, "issuer", "", "issuer URL of the OIDC provider (https)")
	flag.StringVar(&cfg.clientID, "client-id", "", "audience the ID token must carry")
	flag.StringVar(&cfg.usernameClaim, "username-claim", "", "claim that must equal the proxy login")
	flag.BoolVar(&cfg.showVersion, "version", false, "print version information and exit")
	flag.Parse()

	if flag.NArg() > 0 {
		return cfg, fmt.Errorf("unexpected argument %q", flag.Arg(0))
	}
	if cfg.showVersion {
		return cfg, nil
	}
	if err := requireFlags(flag.CommandLine, "issuer", "client-id", "username-claim"); err != nil {
		return cfg, err
	}
	u, err := url.Parse(cfg.issuer)
	if err != nil {
		return cfg, fmt.Errorf("-issuer: %w", err)
	}
	// https only, not http: keys fetched in plaintext can be replaced in transit.
	if u.Scheme != "https" {
		return cfg, fmt.Errorf("-issuer must be an https URL, got %q", cfg.issuer)
	}
	return cfg, nil
}

func requireFlags(fs *flag.FlagSet, names ...string) error {
	var missing []string
	for _, name := range names {
		if fs.Lookup(name).Value.String() == "" {
			missing = append(missing, "-"+name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing %s", strings.Join(missing, ", "))
	}
	return nil
}
