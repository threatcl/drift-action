package config

import (
	"strings"
	"testing"
)

func TestCloudBlockOverlays(t *testing.T) {
	cfg, err := Default().LoadFile(writeConfig(t, `
cloud {
  model            = "payments"
  policy_fail_mode = "on-enforced-violation"
}
`))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if !cfg.Cloud.Declared {
		t.Error("Declared should record that the block was present")
	}
	if cfg.Cloud.Model != "payments" {
		t.Errorf("cloud.model = %q", cfg.Cloud.Model)
	}
	if cfg.Cloud.PolicyFailMode != PolicyFailOnEnforcedViolation {
		t.Errorf("cloud.policy_fail_mode = %q", cfg.Cloud.PolicyFailMode)
	}
}

// An empty block is still a declaration: a fork pull request on a repo that
// configured cloud mode is told it ran unconnected.
func TestCloudBlockEmptyIsDeclared(t *testing.T) {
	cfg, err := Default().LoadFile(writeConfig(t, `cloud {}`))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if !cfg.Cloud.Declared {
		t.Error("an empty cloud block should still count as declared")
	}
	if cfg.Cloud.PolicyFailMode != PolicyFailNever {
		t.Errorf("policy_fail_mode = %q, want the default", cfg.Cloud.PolicyFailMode)
	}
}

func TestNoCloudBlockIsNotDeclared(t *testing.T) {
	cfg, err := Default().LoadFile(writeConfig(t, `fail_mode = "never"`))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if cfg.Cloud.Declared {
		t.Error("Declared set with no cloud block in the file")
	}
}

// The API URL is never read from the config file. That file arrives in the
// pull request under review, and a URL in it would let a pull request send the
// organisation's token to a host of its choosing.
func TestCloudBlockRefusesURL(t *testing.T) {
	_, err := Default().LoadFile(writeConfig(t, `cloud { api_url = "https://evil.example" }`))
	if err == nil {
		t.Fatal("cloud.api_url must be refused")
	}
	if !strings.Contains(err.Error(), "api_url") {
		t.Errorf("error = %v, want it to name the attribute", err)
	}
}

func TestCloudBlockRejectsBadPolicyFailMode(t *testing.T) {
	_, err := Default().LoadFile(writeConfig(t, `cloud { policy_fail_mode = "on-violation" }`))
	if err == nil {
		t.Fatal("expected an error for an unknown policy_fail_mode")
	}
	if !strings.Contains(err.Error(), "cloud.policy_fail_mode must be") {
		t.Errorf("error = %v, want it to name the setting", err)
	}
}

func TestCloudURLFromEnv(t *testing.T) {
	t.Setenv(CloudURLEnv, "http://localhost:8080")
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CloudURL != "http://localhost:8080" {
		t.Errorf("CloudURL = %q", cfg.CloudURL)
	}
}

func TestCloudURLDefault(t *testing.T) {
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CloudURL != DefaultCloudURL {
		t.Errorf("CloudURL = %q, want %q", cfg.CloudURL, DefaultCloudURL)
	}
}

// Plain http carries the token in clear, so it is allowed only to a loopback
// host — the local API during development — and refused anywhere else.
func TestValidateCloudURL(t *testing.T) {
	for _, ok := range []string{
		"https://beta-api.threatcl.com",
		"https://api.example.com/",
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	} {
		if err := ValidateCloudURL(ok); err != nil {
			t.Errorf("ValidateCloudURL(%q) = %v, want accepted", ok, err)
		}
	}
	for _, bad := range []string{
		"http://api.example.com",
		"http://10.0.0.5:8080",
		"ftp://api.example.com",
		"beta-api.threatcl.com",
		"https://user:pass@api.example.com",
		"https://api.example.com/?x=1",
		"",
	} {
		if err := ValidateCloudURL(bad); err == nil {
			t.Errorf("ValidateCloudURL(%q) accepted, want refused", bad)
		}
	}
}

func TestLoadRejectsPlainHTTPCloudURL(t *testing.T) {
	t.Setenv(CloudURLEnv, "http://api.example.com")
	if _, err := Load(t.TempDir()); err == nil || !strings.Contains(err.Error(), CloudURLEnv) {
		t.Fatalf("Load = %v, want a %s error", err, CloudURLEnv)
	}
}
