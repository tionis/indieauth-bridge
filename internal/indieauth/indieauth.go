package indieauth

import (
	"encoding/json"
	"strings"

	"github.com/eric/indieauth-bridge/internal/backends"
	"github.com/eric/indieauth-bridge/internal/config"
)

var SupportedScopes = []string{"profile", "email"}

func ScopeAllowed(scope string) bool {
	if scope == "" {
		return true
	}
	for _, item := range strings.Fields(scope) {
		found := false
		for _, supported := range SupportedScopes {
			if item == supported {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func IdentityAllowed(profile config.ProfileConfig, identity backends.Identity) bool {
	for _, subject := range profile.AllowedSubjects {
		if subject != "" && subject == identity.Subject {
			return true
		}
	}
	for _, username := range profile.AllowedUsernames {
		if username == "" {
			continue
		}
		if strings.EqualFold(username, identity.Username) || strings.EqualFold(username, identity.PreferredUsername) {
			return true
		}
	}
	for _, email := range profile.AllowedEmails {
		if email != "" && strings.EqualFold(email, identity.Email) {
			return true
		}
	}
	for _, allowed := range profile.AllowedGroups {
		for _, actual := range identity.Groups {
			if allowed != "" && allowed == actual {
				return true
			}
		}
	}
	return false
}

func ProfileObject(profile config.ProfileConfig) map[string]any {
	out := map[string]any{
		"url": profile.Me,
	}
	if profile.DisplayName != "" {
		out["name"] = profile.DisplayName
	}
	if profile.Email != "" {
		out["email"] = profile.Email
	}
	return out
}

func ProfileJSON(profile config.ProfileConfig) ([]byte, error) {
	return json.Marshal(ProfileObject(profile))
}
