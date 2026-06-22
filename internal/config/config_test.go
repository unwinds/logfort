package config_test

import (
	"os"
	"testing"

	"github.com/unwinds/logfort/internal/config"
)

func TestLoad_AuthEnabledRequiresCredentials(t *testing.T) {
	t.Setenv("LOGFORT_AUTH_ENABLED", "true")
	t.Setenv("LOGFORT_AUTH_USER", "")
	t.Setenv("LOGFORT_AUTH_PASS", "")

	if _, err := config.Load(); err == nil {
		t.Error("want error when AuthEnabled=true with empty credentials, got nil")
	}
}

func TestLoad_AuthEnabledWithCredentials(t *testing.T) {
	t.Setenv("LOGFORT_AUTH_ENABLED", "true")
	t.Setenv("LOGFORT_AUTH_USER", "admin")
	t.Setenv("LOGFORT_AUTH_PASS", "secret")

	if _, err := config.Load(); err != nil {
		t.Errorf("want no error with valid auth config, got: %v", err)
	}
}

func TestLoad_AuthDisabledEmptyCredentialsOK(t *testing.T) {
	t.Setenv("LOGFORT_AUTH_ENABLED", "false")
	os.Unsetenv("LOGFORT_AUTH_USER")
	os.Unsetenv("LOGFORT_AUTH_PASS")

	if _, err := config.Load(); err != nil {
		t.Errorf("want no error when auth disabled, got: %v", err)
	}
}
