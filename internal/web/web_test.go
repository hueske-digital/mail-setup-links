package web

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"howett.net/plist"

	"github.com/hueske-digital/mail-setup-links/internal/config"
	"github.com/hueske-digital/mail-setup-links/internal/profile"
	"github.com/hueske-digital/mail-setup-links/internal/signing"
)

type fakeSigner struct{ err error }

func (f fakeSigner) Sign(content []byte) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]byte("SIGNED:"), content...), nil
}

type fakeChallenges map[string]string

func (f fakeChallenges) Challenge(token string) (string, bool) {
	response, ok := f[token]
	return response, ok
}

type testApp struct {
	handler   http.Handler
	userAgent string
	now       time.Time
	logs      bytes.Buffer
}

func newApp(t *testing.T, mutate func(*Options)) *testApp {
	t.Helper()
	app := &testApp{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	opts := Options{
		Config: &config.Config{
			PublicURL:       &url.URL{Scheme: "https", Host: "setup.example.com"},
			LinkSecret:      bytes.Repeat([]byte{7}, 32),
			LinkTTL:         30 * 24 * time.Hour,
			MailServer:      profile.MailServer{IMAPHost: "mail.example.net", SMTPHost: "mail.example.net", SMTPPort: 587},
			OrgName:         "Example GmbH",
			ProfileIDPrefix: "com.example.setup",
		},
		Now: func() time.Time { return app.now },
		Log: slog.New(slog.NewJSONHandler(&app.logs, nil)),
	}
	if mutate != nil {
		mutate(&opts)
	}
	handler, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	app.handler = handler
	return app
}

func (a *testApp) do(method, target string, form url.Values) (*http.Response, string) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request := httptest.NewRequest(method, "https://setup.example.com"+target, body)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	request.Header.Set("User-Agent", a.userAgent)
	recorder := httptest.NewRecorder()
	a.handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	content, _ := io.ReadAll(response.Body)
	return response, string(content)
}

var linkPattern = regexp.MustCompile(`https://setup\.example\.com(/e/[A-Za-z0-9_-]+)"`)

func (a *testApp) createLink(t *testing.T, form url.Values) string {
	t.Helper()
	response, body := a.do(http.MethodPost, "/links", form)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("creating link: status %d", response.StatusCode)
	}
	match := linkPattern.FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("no link in response:\n%s", body)
	}
	return match[1]
}

var validForm = url.Values{"email": {"kunde@example.com"}, "displayName": {"Max Mustermann"}}

func TestLinkFlow(t *testing.T) {
	app := newApp(t, nil)

	response, body := app.do(http.MethodGet, "/", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, `action="/links"`) {
		t.Fatalf("generator page: status %d", response.StatusCode)
	}

	response, body = app.do(http.MethodPost, "/links", validForm)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "gültig bis 31.10.2026, 13:00 Uhr (CET)") {
		t.Fatalf("link page: status %d\n%s", response.StatusCode, body)
	}
	path := linkPattern.FindStringSubmatch(body)[1]
	for _, secret := range []string{"kunde", "mail.example.net"} {
		if strings.Contains(path, secret) {
			t.Errorf("link exposes %q", secret)
		}
	}

	response, body = app.do(http.MethodGet, path, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("setup page: status %d", response.StatusCode)
	}
	for _, want := range []string{
		"kunde@example.com", `href="` + path + `/iphone"`, `href="` + path + `/mac"`, `href="` + path + `/outlook"`,
		`href="` + path + `/thunderbird"`, `href="` + path + `/android"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("setup page lacks %q", want)
		}
	}
	if strings.Contains(body, "Passt zu diesem Gerät") {
		t.Error("a client is recommended although the device is unknown")
	}
	if got := response.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("setup page Cache-Control = %q", got)
	}

	response, body = app.do(http.MethodGet, path+"/email.mobileconfig", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("profile: status %d", response.StatusCode)
	}
	if got := response.Header.Get("Content-Type"); got != "application/x-apple-aspen-config" {
		t.Errorf("profile Content-Type = %q", got)
	}
	if got := response.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("profile Cache-Control = %q", got)
	}
	var parsed struct {
		PayloadContent []struct {
			EmailAddress               string
			EmailAccountName           string
			IncomingMailServerUsername string
			IncomingMailServerHostName string
		}
	}
	if _, err := plist.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("profile is not a plist: %v", err)
	}
	payload := parsed.PayloadContent[0]
	if payload.EmailAddress != "kunde@example.com" || payload.EmailAccountName != "Max Mustermann" ||
		payload.IncomingMailServerUsername != "kunde@example.com" || payload.IncomingMailServerHostName != "mail.example.net" {
		t.Errorf("unexpected payload: %+v", payload)
	}
}

func TestClientPagesArePersonalised(t *testing.T) {
	app := newApp(t, nil)
	path := app.createLink(t, validForm)

	cases := map[string][]string{
		"iphone":      {"Einrichten auf <em>iPhone und iPad</em>", `href="` + path + `/email.mobileconfig"`},
		"mac":         {"Einrichten auf dem <em>Mac</em>", `href="` + path + `/email.mobileconfig"`},
		"outlook":     {`data-copy="kunde@example.com"`, `data-copy="mail.example.net"`, "<span>587</span>", "<span>STARTTLS</span>", "<span>993</span>", "Verschlüsselungsmethode"},
		"thunderbird": {`data-copy="Max Mustermann"`, `data-copy="mail.example.net"`, `data-copy="kunde@example.com"`, "Passwort, normal", "Verbindungssicherheit"},
		"android":     {`data-copy="kunde@example.com"`, `data-copy="mail.example.net"`, "Privat (IMAP)", "Sicherheitstyp"},
	}
	for slug, wants := range cases {
		response, body := app.do(http.MethodGet, path+"/"+slug, nil)
		if response.StatusCode != http.StatusOK {
			t.Errorf("%s: status %d", slug, response.StatusCode)
		}
		for _, want := range append(wants, `href="`+path+`"`) {
			if !strings.Contains(body, want) {
				t.Errorf("%s page lacks %q", slug, want)
			}
		}
	}
	for _, slug := range []string{"outlook", "thunderbird", "android"} {
		if _, body := app.do(http.MethodGet, path+"/"+slug, nil); strings.Contains(body, "email.mobileconfig") {
			t.Errorf("%s page offers the Apple profile", slug)
		}
	}
	if response, _ := app.do(http.MethodGet, path+"/windows-phone", nil); response.StatusCode != http.StatusNotFound {
		t.Errorf("unknown client: status %d, want 404", response.StatusCode)
	}
}

func TestFolderPrefixStepFollowsTheConfiguration(t *testing.T) {
	plain := newApp(t, nil)
	prefixed := newApp(t, func(o *Options) {
		cfg := *o.Config
		cfg.MailServer.IMAPPathPrefix = "INBOX"
		o.Config = &cfg
	})
	for _, slug := range []string{"outlook", "thunderbird"} {
		if _, body := plain.do(http.MethodGet, plain.createLink(t, validForm)+"/"+slug, nil); strings.Contains(body, "Ordner synchronisieren") {
			t.Errorf("%s: folder step is shown without a configured prefix", slug)
		}
		if _, body := prefixed.do(http.MethodGet, prefixed.createLink(t, validForm)+"/"+slug, nil); !strings.Contains(body, `data-copy="INBOX"`) {
			t.Errorf("%s: folder step is missing", slug)
		}
	}
}

func TestSetupPageRecommendsTheVisitorsDevice(t *testing.T) {
	app := newApp(t, nil)
	path := app.createLink(t, validForm)
	cases := map[string]string{
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15": "iphone",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15":        "mac",
		"Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36":                 "android",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36":                "outlook",
	}
	for userAgent, slug := range cases {
		app.userAgent = userAgent
		_, body := app.do(http.MethodGet, path, nil)
		recommended := strings.Index(body, `data-client="`+slug+`" class="is-recommended"`)
		first := strings.Index(body, `class="tile"`)
		if recommended < 0 || recommended > first || strings.Count(body, "Passt zu diesem Gerät") != 1 {
			t.Errorf("%s: no single recommended tile at the top", slug)
			continue
		}
		if !strings.HasPrefix(body[first:], `class="tile" href="`+path+"/"+slug+`"`) {
			t.Errorf("%s is not the first tile", slug)
		}
	}
}

func TestWebmailAndSMTPSettingsFollowTheConfiguration(t *testing.T) {
	app := newApp(t, nil)
	if _, body := app.do(http.MethodGet, app.createLink(t, validForm), nil); strings.Contains(body, "Webmail") {
		t.Error("webmail tile is shown without WEBMAIL_URL")
	}

	app = newApp(t, func(o *Options) {
		cfg := *o.Config
		cfg.WebmailURL = "https://webmail.example.net/?_user={email}"
		cfg.MailServer.SMTPPort = 465
		o.Config = &cfg
	})
	path := app.createLink(t, url.Values{"email": {"kunde+test@example.com"}, "displayName": {"Max Mustermann"}})
	if _, body := app.do(http.MethodGet, path, nil); !strings.Contains(body,
		`href="https://webmail.example.net/?_user=kunde%2Btest%40example.com" rel="noopener noreferrer"`) {
		t.Error("webmail tile is missing")
	}
	_, body := app.do(http.MethodGet, path+"/thunderbird", nil)
	if !strings.Contains(body, "<span>465</span>") || strings.Contains(body, "STARTTLS") {
		t.Error("port 465 must be shown with SSL/TLS")
	}
}

func TestProfileIsSignedWhenSignerIsConfigured(t *testing.T) {
	app := newApp(t, func(o *Options) { o.Signer = fakeSigner{} })
	_, body := app.do(http.MethodGet, app.createLink(t, validForm)+"/email.mobileconfig", nil)
	if !strings.HasPrefix(body, "SIGNED:<?xml") {
		t.Errorf("profile was not passed through the signer: %.40q", body)
	}
}

func TestProfileFailsInsteadOfFallingBackToUnsigned(t *testing.T) {
	app := newApp(t, func(o *Options) { o.Signer = fakeSigner{err: signing.ErrUnavailable} })
	response, body := app.do(http.MethodGet, app.createLink(t, validForm)+"/email.mobileconfig", nil)
	if response.StatusCode != http.StatusServiceUnavailable || response.Header.Get("Retry-After") == "" {
		t.Errorf("status %d, Retry-After %q", response.StatusCode, response.Header.Get("Retry-After"))
	}
	if strings.Contains(body, "PayloadContent") {
		t.Error("an unsigned profile was delivered")
	}
}

func TestCreateLinkValidation(t *testing.T) {
	app := newApp(t, nil)
	response, body := app.do(http.MethodPost, "/links", url.Values{
		"email": {"keine-adresse"}, "displayName": {`"><script>alert(1)</script>`},
	})
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", response.StatusCode)
	}
	if !strings.Contains(body, "Bitte eine gültige E-Mail-Adresse eingeben.") || !strings.Contains(body, `aria-invalid="true"`) {
		t.Error("field error is not shown")
	}
	if strings.Contains(body, "<script>alert") {
		t.Error("form value is not escaped")
	}
	if !strings.Contains(body, `value="keine-adresse"`) {
		t.Error("entered value is not kept")
	}
}

func TestLongestAcceptedValuesStillProduceAUsableLink(t *testing.T) {
	app := newApp(t, nil)
	path := app.createLink(t, url.Values{
		"email":       {strings.Repeat("&", 242) + "@example.com"},
		"displayName": {strings.Repeat("&", 100)},
	})
	if response, _ := app.do(http.MethodGet, path, nil); response.StatusCode != http.StatusOK {
		t.Errorf("status %d, want 200", response.StatusCode)
	}
}

func TestCreateLinkRejectsLargeBody(t *testing.T) {
	app := newApp(t, nil)
	response, _ := app.do(http.MethodPost, "/links", url.Values{"email": {strings.Repeat("a", maxFormBytes)}})
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d", response.StatusCode)
	}
}

func TestCreateLinkIsRateLimited(t *testing.T) {
	app := newApp(t, nil)
	for range linkRateLimit {
		app.createLink(t, validForm)
	}
	response, _ := app.do(http.MethodPost, "/links", validForm)
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429", response.StatusCode)
	}
	app.now = app.now.Add(time.Minute)
	app.createLink(t, validForm)
}

func TestInvalidAndExpiredLinks(t *testing.T) {
	app := newApp(t, nil)
	path := app.createLink(t, validForm)

	for _, target := range []string{"/e/AAAA", path[:len(path)-2], path + "AA"} {
		for _, suffix := range []string{"", "/outlook", "/email.mobileconfig"} {
			if response, _ := app.do(http.MethodGet, target+suffix, nil); response.StatusCode != http.StatusNotFound {
				t.Errorf("%s: status %d, want 404", target+suffix, response.StatusCode)
			}
		}
	}

	app.now = app.now.Add(30*24*time.Hour - time.Second)
	if response, _ := app.do(http.MethodGet, path, nil); response.StatusCode != http.StatusOK {
		t.Errorf("before expiry: status %d", response.StatusCode)
	}
	app.now = app.now.Add(time.Second)
	for _, suffix := range []string{"", "/outlook", "/email.mobileconfig"} {
		if response, _ := app.do(http.MethodGet, path+suffix, nil); response.StatusCode != http.StatusGone {
			t.Errorf("after expiry %q: status %d, want 410", suffix, response.StatusCode)
		}
	}
}

func TestLinksOfAnotherKeyAreRejected(t *testing.T) {
	path := newApp(t, nil).createLink(t, validForm)
	other := newApp(t, func(o *Options) {
		cfg := *o.Config
		cfg.LinkSecret = bytes.Repeat([]byte{8}, 32)
		o.Config = &cfg
	})
	if response, _ := other.do(http.MethodGet, path, nil); response.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404", response.StatusCode)
	}
}

func TestUnknownHostsRoutesAndMethodsAreRejected(t *testing.T) {
	app := newApp(t, func(o *Options) { o.Challenges = fakeChallenges{"tok": "tok.auth"} })

	request := httptest.NewRequest(http.MethodGet, "https://evil.example.org/", nil)
	recorder := httptest.NewRecorder()
	app.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMisdirectedRequest {
		t.Errorf("foreign host: status %d, want 421", recorder.Code)
	}

	// Health checks and ACME validation do not use the public host name.
	for target, want := range map[string]string{"/healthz": "ok\n", "/.well-known/acme-challenge/tok": "tok.auth"} {
		request := httptest.NewRequest(http.MethodGet, "http://10.0.0.5:3000"+target, nil)
		recorder := httptest.NewRecorder()
		app.handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || recorder.Body.String() != want {
			t.Errorf("%s: status %d, body %q", target, recorder.Code, recorder.Body.String())
		}
	}

	cases := map[string]struct {
		method, target string
		status         int
	}{
		"unknown route":     {http.MethodGet, "/admin", http.StatusNotFound},
		"unknown asset":     {http.MethodGet, "/assets/secret.txt", http.StatusNotFound},
		"unknown challenge": {http.MethodGet, "/.well-known/acme-challenge/other", http.StatusNotFound},
		"wrong method":      {http.MethodDelete, "/links", http.StatusMethodNotAllowed},
	}
	for name, tc := range cases {
		response, _ := app.do(tc.method, tc.target, nil)
		if response.StatusCode != tc.status {
			t.Errorf("%s: status %d, want %d", name, response.StatusCode, tc.status)
		}
		if got := response.Header.Get("Cache-Control"); got != "no-store" && tc.target != "/.well-known/acme-challenge/other" {
			t.Errorf("%s: Cache-Control = %q", name, got)
		}
	}
}

func TestChallengesAreNotServedWithoutACME(t *testing.T) {
	app := newApp(t, nil)
	if response, _ := app.do(http.MethodGet, "/.well-known/acme-challenge/tok", nil); response.StatusCode != http.StatusNotFound {
		t.Errorf("status %d, want 404", response.StatusCode)
	}
}

func TestSecurityHeadersAndAssetCaching(t *testing.T) {
	app := newApp(t, nil)
	response, _ := app.do(http.MethodGet, "/", nil)
	for header, want := range map[string]string{
		"Content-Security-Policy":   contentSecurityPolicy,
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
		"Strict-Transport-Security": "max-age=31536000",
		"Cache-Control":             "no-store",
	} {
		if got := response.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	response, body := app.do(http.MethodGet, "/assets/style.css", nil)
	if response.StatusCode != http.StatusOK || !strings.Contains(body, "color-scheme") {
		t.Fatalf("stylesheet: status %d", response.StatusCode)
	}
	if got := response.Header.Get("Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("asset Cache-Control = %q", got)
	}
	_, page := app.do(http.MethodGet, "/", nil)
	if !regexp.MustCompile(`<img src="/assets/logo\.svg\?v=[0-9a-f]{12}" alt="Example GmbH" width="385" height="68"`).MatchString(page) {
		t.Error("page shows no logo with dimensions and alternative text")
	}
	versioned := regexp.MustCompile(`/assets/style\.css\?v=[0-9a-f]{12}"`).FindString(page)
	if versioned == "" {
		t.Fatal("stylesheet URL carries no content hash")
	}
	if response, _ := app.do(http.MethodGet, strings.TrimSuffix(versioned, `"`), nil); response.StatusCode != http.StatusOK {
		t.Errorf("versioned stylesheet: status %d", response.StatusCode)
	}
	for asset, contentType := range assetTypes {
		response, body := app.do(http.MethodGet, "/assets/"+asset, nil)
		if response.StatusCode != http.StatusOK || body == "" || response.Header.Get("Content-Type") != contentType {
			t.Errorf("%s: status %d, Content-Type %q", asset, response.StatusCode, response.Header.Get("Content-Type"))
		}
	}
}

func TestLogsContainNoPersonalData(t *testing.T) {
	app := newApp(t, nil)
	path := app.createLink(t, validForm)
	app.do(http.MethodGet, path, nil)
	app.do(http.MethodGet, path+"/email.mobileconfig", nil)

	logs := app.logs.String()
	if !strings.Contains(logs, `"route":"GET /e/{token}"`) {
		t.Errorf("requests are not logged by route:\n%s", logs)
	}
	for _, personal := range []string{"kunde@example.com", "Mustermann", path} {
		if strings.Contains(logs, personal) {
			t.Errorf("logs contain %q", personal)
		}
	}
}
