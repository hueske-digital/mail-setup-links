// Package config reads the service configuration from environment variables.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hueske-digital/mail-setup-links/internal/profile"
	"github.com/hueske-digital/mail-setup-links/internal/token"
)

const letsEncryptDirectory = "https://acme-v02.api.letsencrypt.org/directory"

var (
	hostnamePattern   = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	pathPrefixPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]{0,64}$`)
	idPrefixPattern   = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)*$`)
)

// ACME configures certificate issuance for profile signing.
type ACME struct {
	DirectoryURL string
	Email        string
	DataDir      string
}

// Config is the validated service configuration.
type Config struct {
	PublicURL  *url.URL
	ListenAddr string
	TrustProxy bool
	LinkSecret []byte
	LinkTTL    time.Duration
	MailServer profile.MailServer
	OrgName    string
	// WebmailURL is linked on the setup page; empty hides the link. It may contain the
	// placeholder {email}.
	WebmailURL      string
	ProfileIDPrefix string
	// ACME is nil when profiles are delivered unsigned.
	ACME *ACME
}

// loader collects one error per invalid variable. Messages name the variable and the
// reason, never the value (LINK_SECRET is among them).
type loader struct {
	getenv func(string) string
	errs   []error
}

func (l *loader) fail(name, reason string) {
	l.errs = append(l.errs, fmt.Errorf("%s: %s", name, reason))
}

func (l *loader) optional(name, fallback string) string {
	if value := strings.TrimSpace(l.getenv(name)); value != "" {
		return value
	}
	return fallback
}

func (l *loader) required(name string) string {
	value := l.optional(name, "")
	if value == "" {
		l.fail(name, "is required")
	}
	return value
}

func (l *loader) boolean(name string) bool {
	value, err := strconv.ParseBool(l.optional(name, "false"))
	if err != nil {
		l.fail(name, "must be true or false")
	}
	return value
}

func (l *loader) integer(name string, fallback int, allowed func(int) bool, reason string) int {
	value, err := strconv.Atoi(l.optional(name, strconv.Itoa(fallback)))
	if err != nil || !allowed(value) {
		l.fail(name, reason)
	}
	return value
}

func (l *loader) hostname(name string) string {
	value := strings.ToLower(l.required(name))
	if value != "" && (len(value) > 253 || !hostnamePattern.MatchString(value)) {
		l.fail(name, "must be a hostname")
	}
	return value
}

// Load reads and validates the configuration. getenv is usually os.Getenv.
func Load(getenv func(string) string) (*Config, error) {
	l := &loader{getenv: getenv}
	cfg := &Config{}

	publicURL, err := url.Parse(l.required("PUBLIC_URL"))
	if err != nil || (publicURL.Scheme != "http" && publicURL.Scheme != "https") || publicURL.Host == "" ||
		strings.Trim(publicURL.Path, "/") != "" || publicURL.RawQuery != "" || publicURL.User != nil {
		l.fail("PUBLIC_URL", "must be an http(s) origin without path, e.g. https://setup.example.com")
		publicURL = &url.URL{}
	}
	cfg.PublicURL = &url.URL{Scheme: publicURL.Scheme, Host: publicURL.Host}

	port := l.integer("PORT", 3000, func(v int) bool { return v >= 1 && v <= 65535 }, "must be a port number")
	cfg.ListenAddr = fmt.Sprintf("%s:%d", l.optional("HOST", "0.0.0.0"), port)
	cfg.TrustProxy = l.boolean("TRUST_PROXY")

	cfg.LinkSecret, err = base64.StdEncoding.DecodeString(l.required("LINK_SECRET"))
	if err != nil || len(cfg.LinkSecret) != token.KeySize {
		l.fail("LINK_SECRET", "must be 32 random bytes, base64 encoded")
	}
	ttlDays := l.integer("LINK_TTL_DAYS", 30, func(v int) bool { return v >= 1 && v <= 365 }, "must be between 1 and 365")
	cfg.LinkTTL = time.Duration(ttlDays) * 24 * time.Hour

	cfg.MailServer = profile.MailServer{
		IMAPHost:       l.hostname("MAIL_IMAP_HOST"),
		SMTPHost:       l.hostname("MAIL_SMTP_HOST"),
		IMAPPathPrefix: l.optional("MAIL_IMAP_PATH_PREFIX", ""),
		SMTPPort:       l.integer("MAIL_SMTP_PORT", 465, func(v int) bool { return slices.Contains([]int{465, 587}, v) }, "must be 465 or 587"),
	}

	if !pathPrefixPattern.MatchString(cfg.MailServer.IMAPPathPrefix) {
		l.fail("MAIL_IMAP_PATH_PREFIX", "must consist of at most 64 letters, digits, dots, slashes, dashes or underscores")
	}

	cfg.OrgName = l.required("ORG_NAME")
	if len(cfg.OrgName) > 100 {
		l.fail("ORG_NAME", "must be at most 100 bytes")
	}
	cfg.WebmailURL = l.optional("WEBMAIL_URL", "")
	if webmail, err := url.Parse(cfg.WebmailURL); cfg.WebmailURL != "" && (err != nil || webmail.Scheme != "https" || webmail.Host == "") {
		l.fail("WEBMAIL_URL", "must be an https URL")
	}
	cfg.ProfileIDPrefix = l.optional("PROFILE_ID_PREFIX", reverseHostname(publicURL.Hostname()))
	if len(l.errs) == 0 && !idPrefixPattern.MatchString(cfg.ProfileIDPrefix) {
		l.fail("PROFILE_ID_PREFIX", "must consist of dot separated labels, e.g. com.example.setup")
	}

	switch mode := l.optional("SIGNING_MODE", "off"); mode {
	case "off":
	case "acme":
		cfg.ACME = &ACME{
			DirectoryURL: l.optional("ACME_DIRECTORY_URL", letsEncryptDirectory),
			Email:        l.required("ACME_EMAIL"),
			DataDir:      l.optional("DATA_DIR", "./data"),
		}
		if address, err := mail.ParseAddress(cfg.ACME.Email); cfg.ACME.Email != "" && (err != nil || address.Address != cfg.ACME.Email) {
			l.fail("ACME_EMAIL", "must be an e-mail address")
		}
		if !strings.HasPrefix(cfg.ACME.DirectoryURL, "https://") {
			l.fail("ACME_DIRECTORY_URL", "must be an https URL")
		}
		if !l.boolean("ACME_TOS_AGREED") {
			l.fail("ACME_TOS_AGREED", "must be true to accept the ACME provider's terms of service")
		}
	default:
		l.fail("SIGNING_MODE", "must be off or acme")
	}

	if len(l.errs) > 0 {
		return nil, fmt.Errorf("invalid configuration: %w", errors.Join(l.errs...))
	}
	return cfg, nil
}

func reverseHostname(hostname string) string {
	labels := strings.Split(strings.ToLower(hostname), ".")
	slices.Reverse(labels)
	return strings.Join(labels, ".")
}
