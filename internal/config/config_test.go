package config_test

import (
	"os"
	"testing"

	"github.com/unwinds/sshwatch/internal/config"
)

func TestLoad_AuthEnabledRequiresCredentials(t *testing.T) {
	t.Setenv("SSHWATCH_AUTH_ENABLED", "true")
	t.Setenv("SSHWATCH_AUTH_USER", "")
	t.Setenv("SSHWATCH_AUTH_PASS", "")

	if _, err := config.Load(); err == nil {
		t.Error("want error when AuthEnabled=true with empty credentials, got nil")
	}
}

func TestLoad_AuthEnabledWithCredentials(t *testing.T) {
	t.Setenv("SSHWATCH_AUTH_ENABLED", "true")
	t.Setenv("SSHWATCH_AUTH_USER", "admin")
	t.Setenv("SSHWATCH_AUTH_PASS", "secret")

	if _, err := config.Load(); err != nil {
		t.Errorf("want no error with valid auth config, got: %v", err)
	}
}

func TestLoad_AuthDisabledEmptyCredentialsOK(t *testing.T) {
	t.Setenv("SSHWATCH_AUTH_ENABLED", "false")
	os.Unsetenv("SSHWATCH_AUTH_USER")
	os.Unsetenv("SSHWATCH_AUTH_PASS")

	if _, err := config.Load(); err != nil {
		t.Errorf("want no error when auth disabled, got: %v", err)
	}
}
