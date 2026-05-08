package indieauth

import (
	"testing"

	"github.com/eric/indieauth-bridge/internal/backends"
	"github.com/eric/indieauth-bridge/internal/config"
)

func TestIdentityAllowed(t *testing.T) {
	profile := config.ProfileConfig{
		AllowedSubjects:  []string{"sub"},
		AllowedUsernames: []string{"eric"},
		AllowedEmails:    []string{"eric@example.org"},
		AllowedGroups:    []string{"indieauth"},
	}
	cases := []backends.Identity{
		{Subject: "sub"},
		{PreferredUsername: "Eric"},
		{Email: "ERIC@example.org"},
		{Groups: []string{"indieauth"}},
	}
	for _, identity := range cases {
		if !IdentityAllowed(profile, identity) {
			t.Fatalf("expected identity to be allowed: %+v", identity)
		}
	}
	if IdentityAllowed(profile, backends.Identity{Subject: "other", Email: "other@example.org"}) {
		t.Fatal("unexpected identity allowed")
	}
}

func TestScopeAllowed(t *testing.T) {
	if !ScopeAllowed("") || !ScopeAllowed("profile email") {
		t.Fatal("expected supported scopes")
	}
	if ScopeAllowed("profile create") {
		t.Fatal("unsupported scope accepted")
	}
}
