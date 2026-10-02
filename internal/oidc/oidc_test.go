package oidc

import (
	"testing"

	"github.com/abhinavxd/libredesk/internal/oidc/models"
	"github.com/abhinavxd/libredesk/internal/testutil"
)

func newTestManager(t *testing.T, envID, envSecret string) *Manager {
	return &Manager{i18n: testutil.NewI18n(t), envClientID: envClientID(envID, envSecret)}
}

func TestSecretFromEnv(t *testing.T) {
	tests := []struct {
		name, envID, envSecret, clientID string
		want                             bool
	}{
		{"matching id", "zitadel", "s", "zitadel", true},
		{"non-matching id", "zitadel", "s", "google", false},
		{"unset", "", "", "zitadel", false},
		{"id without secret", "zitadel", "", "zitadel", false},
		{"secret without id", "", "s", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := newTestManager(t, tc.envID, tc.envSecret).secretFromEnv(tc.clientID); got != tc.want {
				t.Errorf("secretFromEnv(%q) = %v, want %v", tc.clientID, got, tc.want)
			}
		})
	}
}

func TestLockEnvCredentials(t *testing.T) {
	o := newTestManager(t, "zitadel", "from-env")
	current := models.OIDC{ClientID: "zitadel", ClientSecret: "stored"}

	t.Run("empty secret keeps stored", func(t *testing.T) {
		got, err := o.lockEnvCredentials(current, models.OIDC{Name: "renamed", ClientID: "zitadel"})
		if err != nil {
			t.Fatal(err)
		}
		if got.ClientSecret != "stored" || got.Name != "renamed" {
			t.Errorf("got %+v", got)
		}
	})
	t.Run("client id change rejected", func(t *testing.T) {
		if _, err := o.lockEnvCredentials(current, models.OIDC{ClientID: "other"}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("new secret rejected", func(t *testing.T) {
		if _, err := o.lockEnvCredentials(current, models.OIDC{ClientID: "zitadel", ClientSecret: "new"}); err == nil {
			t.Error("expected error")
		}
	})
	t.Run("provider not env-managed is untouched", func(t *testing.T) {
		req := models.OIDC{ClientID: "other", ClientSecret: "new"}
		got, err := o.lockEnvCredentials(models.OIDC{ClientID: "google", ClientSecret: "stored"}, req)
		if err != nil || got != req {
			t.Errorf("got %+v, %v", got, err)
		}
	})
}

func TestValidateCredentialsEnvManaged(t *testing.T) {
	o := newTestManager(t, "zitadel", "from-env")
	if err := o.validateCredentials(models.OIDC{ClientID: "zitadel"}); err != nil {
		t.Errorf("env-managed provider without secret: %v", err)
	}
	if err := o.validateCredentials(models.OIDC{ClientID: "google"}); err == nil {
		t.Error("expected error for missing secret on non-env provider")
	}
	if err := o.validateCredentials(models.OIDC{ClientSecret: "s"}); err == nil {
		t.Error("expected error for missing client id")
	}
}
