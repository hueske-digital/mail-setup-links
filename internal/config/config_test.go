package config

import (
	"maps"
	"strings"
	"testing"
	"time"
)

const testSecret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // "0123456789abcdef" twice, test only

func env(overrides map[string]string) func(string) string {
	values := map[string]string{
		"PUBLIC_URL":     "https://setup.example.com",
		"LINK_SECRET":    testSecret,
		"MAIL_IMAP_HOST": "Mail.Example.net",
		"MAIL_SMTP_HOST": "mail.example.net",
		"ORG_NAME":       "Example GmbH",
	}
	maps.Copy(values, overrides)
	return func(name string) string { return values[name] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL.String() != "https://setup.example.com" || cfg.ListenAddr != "0.0.0.0:3000" {
		t.Errorf("unexpected address settings: %s %s", cfg.PublicURL, cfg.ListenAddr)
	}
	if cfg.LinkTTL != 30*24*time.Hour || cfg.TrustProxy || cfg.ACME != nil {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
	if cfg.MailServer.IMAPHost != "mail.example.net" || cfg.MailServer.SMTPPort != 465 {
		t.Errorf("unexpected mail server: %+v", cfg.MailServer)
	}
	if cfg.ProfileIDPrefix != "com.example.setup" {
		t.Errorf("unexpected id prefix %q", cfg.ProfileIDPrefix)
	}
}

func TestLoadLocalDevelopmentURL(t *testing.T) {
	cfg, err := Load(env(map[string]string{"PUBLIC_URL": "http://localhost:3000"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL.Host != "localhost:3000" || cfg.ProfileIDPrefix != "localhost" {
		t.Errorf("unexpected config: %s %q", cfg.PublicURL, cfg.ProfileIDPrefix)
	}
}

func TestLoadACME(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		"SIGNING_MODE": "acme", "ACME_EMAIL": "hostmaster@example.com", "ACME_TOS_AGREED": "true",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ACME == nil || cfg.ACME.DirectoryURL != letsEncryptDirectory || cfg.ACME.DataDir != "./data" {
		t.Errorf("unexpected ACME config: %+v", cfg.ACME)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]struct {
		overrides map[string]string
		variable  string
	}{
		"missing public url":   {map[string]string{"PUBLIC_URL": ""}, "PUBLIC_URL"},
		"public url with path": {map[string]string{"PUBLIC_URL": "https://example.com/setup"}, "PUBLIC_URL"},
		"short secret":         {map[string]string{"LINK_SECRET": "c2hvcnQ="}, "LINK_SECRET"},
		"imap host is no fqdn": {map[string]string{"MAIL_IMAP_HOST": "localhost"}, "MAIL_IMAP_HOST"},
		"webmail over http":    {map[string]string{"WEBMAIL_URL": "http://webmail.example.net"}, "WEBMAIL_URL"},
		"id prefix":            {map[string]string{"PROFILE_ID_PREFIX": "Com.Example/x"}, "PROFILE_ID_PREFIX"},
		"imap path prefix":     {map[string]string{"MAIL_IMAP_PATH_PREFIX": "IN BOX"}, "MAIL_IMAP_PATH_PREFIX"},
		"smtp port":            {map[string]string{"MAIL_SMTP_PORT": "25"}, "MAIL_SMTP_PORT"},
		"ttl":                  {map[string]string{"LINK_TTL_DAYS": "0"}, "LINK_TTL_DAYS"},
		"signing mode":         {map[string]string{"SIGNING_MODE": "file"}, "SIGNING_MODE"},
		"acme without email":   {map[string]string{"SIGNING_MODE": "acme", "ACME_TOS_AGREED": "true"}, "ACME_EMAIL"},
		"acme without tos":     {map[string]string{"SIGNING_MODE": "acme", "ACME_EMAIL": "a@example.com"}, "ACME_TOS_AGREED"},
		"acme over http":       {map[string]string{"SIGNING_MODE": "acme", "ACME_EMAIL": "a@example.com", "ACME_TOS_AGREED": "true", "ACME_DIRECTORY_URL": "http://ca.example.com/dir"}, "ACME_DIRECTORY_URL"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(env(tc.overrides))
			if err == nil || !strings.Contains(err.Error(), tc.variable+":") {
				t.Fatalf("got %v, want an error naming %s", err, tc.variable)
			}
		})
	}
}

func TestErrorsDoNotLeakTheSecret(t *testing.T) {
	_, err := Load(env(map[string]string{"LINK_SECRET": "bm90LXRoaXJ0eS10d28tYnl0ZXM=", "ORG_NAME": ""}))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "bm90LXRoaXJ0eS10d28tYnl0ZXM") {
		t.Errorf("error leaks the secret: %v", err)
	}
}
