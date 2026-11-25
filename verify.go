package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/coreos/go-oidc/v3/oidc"
)

type outcome int

const (
	accepted outcome = iota
	rejected
	broken
)

type verdict struct {
	outcome outcome
	groups  []string
	reason  string
}

type authenticator struct {
	cfg      config
	client   *http.Client
	fetches  *fetchRecorder
	verifier *oidc.IDTokenVerifier
}

func newAuthenticator(cfg config, transport http.RoundTripper) *authenticator {
	rec := &fetchRecorder{next: transport}
	return &authenticator{
		cfg:     cfg,
		client:  &http.Client{Transport: rec, Timeout: fetchTimeout},
		fetches: rec,
	}
}

func (a *authenticator) check(login, token string) verdict {
	if a.verifier == nil {
		// Discovery on first use, not at startup: a helper that exits while
		// the issuer is down makes Squid stop ("helpers crashing too rapidly").
		if err := a.discover(); err != nil {
			return verdict{outcome: broken, reason: err.Error()}
		}
	}

	claims, err := a.verify(token)
	if err != nil {
		if a.fetches.failed() {
			return verdict{outcome: broken, reason: err.Error()}
		}
		return verdict{outcome: rejected, reason: err.Error()}
	}

	// The login is what Squid logs as %ul; without this check anyone could
	// log in under another name with their own token.
	name, _ := claims[a.cfg.usernameClaim].(string)
	if name == "" || name != login {
		return verdict{outcome: rejected, reason: fmt.Sprintf("login does not match claim %s", a.cfg.usernameClaim)}
	}

	groups, err := stringList(claims["groups"])
	if err != nil {
		return verdict{outcome: rejected, reason: err.Error()}
	}
	return verdict{outcome: accepted, groups: groups}
}

func (a *authenticator) discover() error {
	ctx, cancel := context.WithTimeout(oidc.ClientContext(context.Background(), a.client), fetchTimeout)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, a.cfg.issuer)
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	a.verifier = provider.VerifierContext(oidc.ClientContext(context.Background(), a.client), &oidc.Config{
		ClientID: a.cfg.clientID,
		// Fixed, not taken from discovery: Dex signs with RS256 only, and a
		// fixed list keeps "none" and HMAC out whatever the provider advertises.
		SupportedSigningAlgs: []string{oidc.RS256},
	})
	return nil
}

func (a *authenticator) verify(token string) (map[string]any, error) {
	a.fetches.reset()
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	idToken, err := a.verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// No claim means no groups, not an error: Dex omits it for a user in none.
func stringList(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, errors.New("groups claim is not a list")
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, errors.New("groups claim holds a non-string")
		}
		out = append(out, s)
	}
	return out, nil
}

// fetchRecorder notes whether a request to the issuer failed while verifying
// one token. That tells BH (we could not fetch keys) from ERR (the token is
// bad) without matching go-oidc's error strings, which change across versions.
type fetchRecorder struct {
	next http.RoundTripper
	seen atomic.Bool
}

func (f *fetchRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := f.next.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		f.seen.Store(true)
	}
	return resp, err
}

func (f *fetchRecorder) reset()       { f.seen.Store(false) }
func (f *fetchRecorder) failed() bool { return f.seen.Load() }
