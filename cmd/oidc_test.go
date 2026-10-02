package main

import (
	"testing"

	oidcmodels "github.com/abhinavxd/libredesk/internal/oidc/models"
)

func TestToAuthProvidersSecretOverride(t *testing.T) {
	configs := []oidcmodels.OIDC{
		{ID: 1, Enabled: true, ClientID: "zitadel", ClientSecret: "stored-1"},
		{ID: 2, Enabled: true, ClientID: "google", ClientSecret: "stored-2"},
		{ID: 3, Enabled: false, ClientID: "zitadel", ClientSecret: "stored-3"},
	}

	tests := []struct {
		name, clientID, secret string
		want                   map[int]string
	}{
		{"matching id uses configured secret", "zitadel", "from-env", map[int]string{1: "from-env", 2: "stored-2"}},
		{"non-matching id keeps stored secret", "other", "from-env", map[int]string{1: "stored-1", 2: "stored-2"}},
		{"unset keeps stored secret", "", "", map[int]string{1: "stored-1", 2: "stored-2"}},
		{"secret without id keeps stored secret", "", "from-env", map[int]string{1: "stored-1", 2: "stored-2"}},
		{"id without secret keeps stored secret", "zitadel", "", map[int]string{1: "stored-1", 2: "stored-2"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := toAuthProviders(configs, tc.clientID, tc.secret)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d providers, want %d", len(got), len(tc.want))
			}
			for _, p := range got {
				if p.ClientSecret != tc.want[p.ID] {
					t.Errorf("provider %d: secret %q, want %q", p.ID, p.ClientSecret, tc.want[p.ID])
				}
			}
		})
	}
}
