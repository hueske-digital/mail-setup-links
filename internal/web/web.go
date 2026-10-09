// Package web serves the link generator, the customer setup page and the profile download.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // the image has no zoneinfo; expiry dates are shown in Europe/Berlin

	"github.com/hueske-digital/mail-setup-links/internal/config"
	"github.com/hueske-digital/mail-setup-links/internal/profile"
	"github.com/hueske-digital/mail-setup-links/internal/signing"
	"github.com/hueske-digital/mail-setup-links/internal/token"
)

const (
	maxFormBytes = 8 << 10
	// Per client and minute.
	pageRateLimit = 120
	linkRateLimit = 10

	contentSecurityPolicy = "default-src 'none'; style-src 'self'; font-src 'self'; script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)

//go:embed templates/*.html
var templateFiles embed.FS

//go:embed static
var staticFiles embed.FS

// assetTypes lists every embedded file that is served, with its content type.
var assetTypes = map[string]string{
	"style.css":                         "text/css; charset=utf-8",
	"app.js":                            "text/javascript; charset=utf-8",
	"fonts/Mona-Sans.woff2":             "font/woff2",
	"fonts/DMSerifDisplay-Italic.woff2": "font/woff2",
}

// Signer wraps a profile in a CMS signature.
type Signer interface {
	Sign(content []byte) ([]byte, error)
}

// ChallengeSource resolves pending ACME HTTP-01 challenge tokens.
type ChallengeSource interface {
	Challenge(token string) (string, bool)
}

// Options are the dependencies of the HTTP handler.
type Options struct {
	Config *config.Config
	// Signer is nil when profiles are delivered unsigned.
	Signer Signer
	// Challenges is nil when no ACME challenges are served.
	Challenges ChallengeSource
	Now        func() time.Time
	Log        *slog.Logger
}

type server struct {
	Options
	codec     *token.Codec
	templates map[string]*template.Template
	location  *time.Location
}

// linkPayload is the content of a link token.
type linkPayload struct {
	profile.Account
	Expires int64 `json:"x"`
}

// New returns the HTTP handler of the service.
func New(opts Options) (http.Handler, error) {
	codec, err := token.New(opts.Config.LinkSecret)
	if err != nil {
		return nil, err
	}
	location, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		return nil, err
	}
	assets, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, err
	}
	// Asset URLs carry a content hash, so a new release is not served from browser caches.
	assetURLs := map[string]string{}
	for asset := range assetTypes {
		content, err := fs.ReadFile(assets, asset)
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(content)
		assetURLs[asset] = "/assets/" + asset + "?v=" + hex.EncodeToString(digest[:6])
	}
	funcs := template.FuncMap{"asset": func(name string) string { return assetURLs[name] }}

	s := &server{Options: opts, codec: codec, templates: map[string]*template.Template{}, location: location}
	for _, page := range []string{"generator", "link", "chooser", "client", "message"} {
		s.templates[page], err = template.New("layout.html").Funcs(funcs).
			ParseFS(templateFiles, "templates/layout.html", "templates/"+page+".html")
		if err != nil {
			return nil, err
		}
	}

	pages := newRateLimiter(pageRateLimit, time.Minute, opts.Now)
	links := newRateLimiter(linkRateLimit, time.Minute, opts.Now)

	// Routes and methods not listed here are answered with 404/405 by the mux.
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", s.limit(pages, s.handleGenerator))
	mux.Handle("POST /links", s.limit(links, s.handleCreateLink))
	mux.Handle("GET /e/{token}", s.limit(pages, s.handleSetup))
	mux.Handle("GET /e/{token}/email.mobileconfig", s.limit(pages, s.handleProfile))
	mux.Handle("GET /e/{token}/{client}", s.limit(pages, s.handleClient))
	for asset, contentType := range assetTypes {
		mux.Handle("GET /assets/"+asset, s.limit(pages, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Cache-Control", "public, max-age=3600")
			http.ServeFileFS(w, r, assets, asset)
		}))
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	if opts.Challenges != nil {
		mux.HandleFunc("GET /.well-known/acme-challenge/{token}", s.handleChallenge)
	}
	return s.logRequests(s.checkHost(s.securityHeaders(mux))), nil
}

// --- middleware ---

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// logRequests logs the matched route pattern, not the path: no addresses, no client IPs.
func (s *server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		s.Log.Info("request", "method", r.Method, "route", r.Pattern, "status", recorder.status,
			"durationMs", time.Since(start).Milliseconds())
	})
}

// checkHost rejects requests for hosts other than the public one. Health checks and ACME
// validation reach the service under other names and are exempt.
func (s *server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exempt := r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		if !exempt && !strings.EqualFold(s.requestHost(r), s.Config.PublicURL.Host) {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) requestHost(r *http.Request) string {
	if s.Config.TrustProxy {
		if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
			return forwarded
		}
	}
	return r.Host
}

func (s *server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Content-Security-Policy", contentSecurityPolicy)
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		// Pages are personalised or answer a form; only static assets opt into caching.
		header.Set("Cache-Control", "no-store")
		if s.Config.PublicURL.Scheme == "https" {
			header.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP is only used as rate limit key. Behind the trusted proxy the last
// X-Forwarded-For entry is the address that proxy saw.
func (s *server) clientIP(r *http.Request) string {
	if s.Config.TrustProxy {
		if forwarded := r.Header.Values("X-Forwarded-For"); len(forwarded) > 0 {
			entries := strings.Split(forwarded[len(forwarded)-1], ",")
			return strings.TrimSpace(entries[len(entries)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *server) limit(limiter *rateLimiter, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(s.clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			s.renderMessage(w, r, http.StatusTooManyRequests, "Zu viele Anfragen", "Bitte versuche es in einer Minute erneut.")
			return
		}
		next(w, r)
	})
}

// rateLimiter counts requests per key in fixed windows.
type rateLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu     sync.Mutex
	resets time.Time
	counts map[string]int
}

func newRateLimiter(limit int, window time.Duration, now func() time.Time) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, now: now, counts: map[string]int{}}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := l.now(); !now.Before(l.resets) {
		clear(l.counts)
		l.resets = now.Add(l.window)
	}
	l.counts[key]++
	return l.counts[key] <= l.limit
}

// --- pages ---

type formField struct {
	Name     string
	Label    string
	Type     string
	Hint     string
	Required bool
	Value    string
	Error    string
}

func (f formField) DescribedBy() string {
	var ids []string
	if f.Hint != "" {
		ids = append(ids, f.Name+"-hint")
	}
	if f.Error != "" {
		ids = append(ids, f.Name+"-error")
	}
	return strings.Join(ids, " ")
}

var fieldErrors = map[string]string{
	profile.FieldEmail:       "Bitte eine gültige E-Mail-Adresse eingeben.",
	profile.FieldDisplayName: "Bitte einen Anzeigenamen mit höchstens 100 Zeichen eingeben.",
}

func (s *server) render(w http.ResponseWriter, r *http.Request, status int, page string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.templates[page].ExecuteTemplate(w, "layout.html", data); err != nil {
		s.Log.Error("rendering page failed", "route", r.Pattern, "page", page, "error", err)
	}
}

func (s *server) renderMessage(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	s.render(w, r, status, "message", struct{ OrgName, Title, Message string }{s.Config.OrgName, title, message})
}

func (s *server) renderGenerator(w http.ResponseWriter, r *http.Request, status int, values map[string]string, invalid []string) {
	fields := []formField{
		{Name: profile.FieldEmail, Label: "E-Mail-Adresse", Type: "email", Required: true},
		{Name: profile.FieldDisplayName, Label: "Anzeigename", Type: "text", Required: true,
			Hint: "Erscheint bei Empfängern als Absender."},
	}
	for i := range fields {
		fields[i].Value = values[fields[i].Name]
	}
	for _, name := range invalid {
		for i := range fields {
			if fields[i].Name == name {
				fields[i].Error = fieldErrors[name]
			}
		}
	}
	s.render(w, r, status, "generator", struct {
		OrgName string
		Fields  []formField
	}{s.Config.OrgName, fields})
}

func (s *server) handleGenerator(w http.ResponseWriter, r *http.Request) {
	s.renderGenerator(w, r, http.StatusOK, nil, nil)
}

func (s *server) handleCreateLink(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		status := http.StatusBadRequest
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			status = http.StatusRequestEntityTooLarge
		}
		s.renderMessage(w, r, status, "Ungültige Anfrage", "Das Formular konnte nicht verarbeitet werden.")
		return
	}
	values := map[string]string{
		profile.FieldEmail:       strings.TrimSpace(r.PostForm.Get(profile.FieldEmail)),
		profile.FieldDisplayName: strings.TrimSpace(r.PostForm.Get(profile.FieldDisplayName)),
	}
	account := profile.Account{
		Email:       values[profile.FieldEmail],
		DisplayName: values[profile.FieldDisplayName],
	}
	if invalid := account.Validate(); len(invalid) > 0 {
		s.renderGenerator(w, r, http.StatusBadRequest, values, invalid)
		return
	}

	expires := s.Now().Add(s.Config.LinkTTL)
	sealed, err := s.codec.Seal(linkPayload{Account: account, Expires: expires.Unix()})
	if err != nil {
		s.Log.Error("sealing link failed", "error", err)
		s.renderMessage(w, r, http.StatusInternalServerError, "Fehler", "Der Link konnte nicht erstellt werden.")
		return
	}
	s.render(w, r, http.StatusOK, "link", struct{ OrgName, Email, Link, Expires string }{
		OrgName: s.Config.OrgName,
		Email:   account.Email,
		Link:    s.Config.PublicURL.JoinPath("e", sealed).String(),
		Expires: expires.In(s.location).Format("02.01.2006, 15:04 Uhr (MST)"),
	})
}

// resolve returns the account of the link token in the request. If the link is invalid or
// expired it renders the error page and returns false.
func (s *server) resolve(w http.ResponseWriter, r *http.Request) (profile.Account, bool) {
	var payload linkPayload
	if err := s.codec.Open(r.PathValue("token"), &payload); err != nil || len(payload.Validate()) > 0 {
		s.renderMessage(w, r, http.StatusNotFound, "Link ungültig",
			"Dieser Einrichtungslink ist nicht gültig. Bitte fordere einen neuen Link an.")
		return profile.Account{}, false
	}
	if !s.Now().Before(time.Unix(payload.Expires, 0)) {
		s.renderMessage(w, r, http.StatusGone, "Link abgelaufen",
			"Dieser Einrichtungslink ist abgelaufen. Bitte fordere einen neuen Link an.")
		return profile.Account{}, false
	}
	return payload.Account, true
}

// tile is one choice on the setup page.
type tile struct {
	Slug        string
	Href        string
	Name        string
	Summary     string
	Icon        string
	Recommended bool
	External    bool
}

// handleSetup lets the customer pick a device or mail program. The one matching the
// visitor's device is listed first.
func (s *server) handleSetup(w http.ResponseWriter, r *http.Request) {
	account, ok := s.resolve(w, r)
	if !ok {
		return
	}
	detected := detectClient(r.UserAgent())
	var tiles []tile
	for _, candidate := range clients {
		entry := tile{
			Slug:        candidate.Slug,
			Href:        "/e/" + r.PathValue("token") + "/" + candidate.Slug,
			Name:        candidate.Name,
			Summary:     candidate.Summary,
			Icon:        candidate.Icon,
			Recommended: candidate.Slug == detected,
		}
		if entry.Recommended {
			tiles = append([]tile{entry}, tiles...)
		} else {
			tiles = append(tiles, entry)
		}
	}
	if s.Config.WebmailURL != "" {
		// The placeholder prefills the webmail login, e.g. Roundcube's "?_user={email}".
		href := strings.ReplaceAll(s.Config.WebmailURL, "{email}", url.QueryEscape(account.Email))
		tiles = append(tiles, tile{
			Slug: "webmail", Href: href, Name: "Webmail", Summary: "Im Browser, ohne Einrichtung",
			Icon: "globe", External: true,
		})
	}
	s.render(w, r, http.StatusOK, "chooser", struct {
		OrgName string
		Account profile.Account
		Tiles   []tile
	}{s.Config.OrgName, account, tiles})
}

// handleClient shows the personalised instructions for one device or mail program.
func (s *server) handleClient(w http.ResponseWriter, r *http.Request) {
	account, ok := s.resolve(w, r)
	if !ok {
		return
	}
	selected, found := findClient(r.PathValue("client"))
	if !found {
		s.renderMessage(w, r, http.StatusNotFound, "Seite nicht gefunden", "Diese Anleitung gibt es nicht.")
		return
	}
	base := "/e/" + r.PathValue("token")
	s.render(w, r, http.StatusOK, "client", struct {
		OrgName, HeadingPrefix, Name, Email string
		BackPath, ProfilePath               string
		Steps                               []step
	}{
		OrgName:       s.Config.OrgName,
		HeadingPrefix: selected.HeadingPrefix,
		Name:          selected.Name,
		Email:         account.Email,
		BackPath:      base,
		ProfilePath:   base + "/email.mobileconfig",
		Steps:         selected.steps(account, s.Config.MailServer),
	})
}

func (s *server) handleProfile(w http.ResponseWriter, r *http.Request) {
	account, ok := s.resolve(w, r)
	if !ok {
		return
	}
	body, err := profile.Build(account, s.Config.MailServer, profile.Options{
		OrgName: s.Config.OrgName, IDPrefix: s.Config.ProfileIDPrefix,
	})
	if err == nil && s.Signer != nil {
		body, err = s.Signer.Sign(body)
	}
	switch {
	case errors.Is(err, signing.ErrUnavailable):
		// Signing is configured, so an unsigned profile would hide the failure.
		s.Log.Error("profile requested without a valid signing certificate")
		w.Header().Set("Retry-After", "60")
		s.renderMessage(w, r, http.StatusServiceUnavailable, "Vorübergehend nicht verfügbar",
			"Das Profil kann gerade nicht bereitgestellt werden. Bitte versuche es in einigen Minuten erneut.")
		return
	case err != nil:
		s.Log.Error("building profile failed", "error", err)
		s.renderMessage(w, r, http.StatusInternalServerError, "Fehler", "Das Profil konnte nicht erstellt werden.")
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="email.mobileconfig"`)
	_, _ = w.Write(body)
}

func (s *server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	response, ok := s.Challenges.Challenge(r.PathValue("token"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(response))
}
