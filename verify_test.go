package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestRefusesTokensThatMustNotAuthenticate(t *testing.T) {
	iss := newTestIssuer(t)
	other := newTestIssuer(t)
	auth := helperFor(iss)

	cases := map[string]struct{ login, token string }{
		"expired":        {"alice", iss.expired(t, "alice")},
		"wrong audience": {"alice", iss.forAudience(t, "alice", "other-app")},
		"wrong issuer":   {"alice", other.valid(t, "alice")},
		"foreign key":    {"alice", other.posingAs(t, iss, "alice")},
		"alg none":       {"alice", iss.unsigned(t, "alice")},
		"tampered":       {"alice", iss.tampered(t, "alice")},
		"login mismatch": {"bob", iss.valid(t, "alice")},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if v := auth.check(c.login, c.token); v.outcome != rejected {
				t.Fatalf("outcome = %v (%s), want rejected", v.outcome, v.reason)
			}
		})
	}
}

func TestAcceptsValidTokenWithItsGroups(t *testing.T) {
	iss := newTestIssuer(t)
	auth := helperFor(iss)

	v := auth.check("alice", iss.valid(t, "alice", "web", "data"))
	if v.outcome != accepted || !slices.Equal(v.groups, []string{"web", "data"}) {
		t.Fatalf("got %v %v (%s), want accepted with web, data", v.outcome, v.groups, v.reason)
	}
}

func TestAcceptsTokenWithoutGroupsClaim(t *testing.T) {
	iss := newTestIssuer(t)
	auth := helperFor(iss)

	v := auth.check("alice", iss.valid(t, "alice"))
	if v.outcome != accepted || len(v.groups) != 0 {
		t.Fatalf("got %v %v (%s), want accepted without groups", v.outcome, v.groups, v.reason)
	}
}

func TestBrokenWhenIssuerIsUnreachable(t *testing.T) {
	iss := newTestIssuer(t)
	auth := helperFor(iss)
	token := iss.valid(t, "alice", "web")
	iss.srv.Close()

	if v := auth.check("alice", token); v.outcome != broken {
		t.Fatalf("outcome = %v (%s), want broken", v.outcome, v.reason)
	}
}

func TestBrokenWhenKeysCannotBeFetched(t *testing.T) {
	iss := newTestIssuer(t)
	auth := helperFor(iss)
	if v := auth.check("alice", iss.valid(t, "alice", "web")); v.outcome != accepted {
		t.Fatalf("setup: outcome = %v (%s), want accepted", v.outcome, v.reason)
	}
	iss.keysBroken.Store(true)

	// An unknown key ID makes the helper refetch the key set.
	if v := auth.check("alice", iss.underUnpublishedKey(t, "alice")); v.outcome != broken {
		t.Fatalf("outcome = %v (%s), want broken", v.outcome, v.reason)
	}
}

// The helpers below are a test OIDC provider: discovery, a key set, and a
// signer for tokens with arbitrary claims. serve_test.go uses them too.

const testClientID = "squid-relay"

type testIssuer struct {
	srv        *httptest.Server
	key        *rsa.PrivateKey
	keysBroken atomic.Bool
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss := &testIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", iss.discovery)
	mux.HandleFunc("/keys", iss.keys)
	iss.srv = httptest.NewTLSServer(mux)
	t.Cleanup(iss.srv.Close)
	return iss
}

func (iss *testIssuer) url() string { return iss.srv.URL }

func (iss *testIssuer) discovery(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                iss.url(),
		"jwks_uri":                              iss.url() + "/keys",
		"authorization_endpoint":                iss.url() + "/auth",
		"token_endpoint":                        iss.url() + "/token",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (iss *testIssuer) keys(w http.ResponseWriter, _ *http.Request) {
	if iss.keysBroken.Load() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &iss.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig",
	}}})
}

// claims returns a valid claim set for login; tests change what they probe.
func (iss *testIssuer) claims(login string, groups ...string) map[string]any {
	c := map[string]any{
		"iss":                iss.url(),
		"aud":                testClientID,
		"sub":                "sub-" + login,
		"exp":                time.Now().Add(5 * time.Minute).Unix(),
		"iat":                time.Now().Unix(),
		"preferred_username": login,
	}
	if groups != nil {
		c["groups"] = groups
	}
	return c
}

func (iss *testIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	return iss.signWithKID(t, claims, "k1")
}

func (iss *testIssuer) signWithKID(t *testing.T, claims map[string]any, kid string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: iss.key},
		(&jose.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// valid is a token the helper must accept.
func (iss *testIssuer) valid(t *testing.T, login string, groups ...string) string {
	t.Helper()
	return iss.sign(t, iss.claims(login, groups...))
}

func (iss *testIssuer) expired(t *testing.T, login string) string {
	t.Helper()
	c := iss.claims(login)
	c["exp"] = time.Now().Add(-time.Second).Unix()
	return iss.sign(t, c)
}

func (iss *testIssuer) forAudience(t *testing.T, login, aud string) string {
	t.Helper()
	c := iss.claims(login)
	c["aud"] = aud
	return iss.sign(t, c)
}

// posingAs signs with this issuer's key a token that names victim as issuer,
// under the key ID victim publishes.
func (iss *testIssuer) posingAs(t *testing.T, victim *testIssuer, login string) string {
	t.Helper()
	c := iss.claims(login)
	c["iss"] = victim.url()
	return iss.signWithKID(t, c, "k1")
}

// underUnpublishedKey is signed under a key ID the issuer does not publish,
// as after a key rotation.
func (iss *testIssuer) underUnpublishedKey(t *testing.T, login string) string {
	t.Helper()
	return iss.signWithKID(t, iss.claims(login), "rotated")
}

// unsigned is a valid claim set with alg "none" and an empty signature.
func (iss *testIssuer) unsigned(t *testing.T, login string) string {
	t.Helper()
	payload, err := json.Marshal(iss.claims(login))
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc(payload) + "."
}

// tampered is a valid token whose login was changed after signing.
func (iss *testIssuer) tampered(t *testing.T, login string) string {
	t.Helper()
	parts := strings.Split(iss.valid(t, login), ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	altered := strings.Replace(string(payload), `"preferred_username":"`, `"preferred_username":"x`, 1)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(altered))
	return strings.Join(parts, ".")
}

// helperFor returns a helper trusting iss, as Squid would run it.
func helperFor(iss *testIssuer) *authenticator {
	cfg := config{issuer: iss.url(), clientID: testClientID, usernameClaim: "preferred_username"}
	return newAuthenticator(cfg, iss.srv.Client().Transport)
}
