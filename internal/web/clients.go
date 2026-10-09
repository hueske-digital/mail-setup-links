package web

import (
	"strconv"
	"strings"

	"github.com/hueske-digital/mail-setup-links/internal/profile"
)

// value is one setting the customer has to enter; copyable ones get a copy button.
type value struct {
	Label string
	Value string
	Copy  bool
}

// step is one numbered instruction. Download marks the step that offers the profile.
type step struct {
	Title    string
	Text     string
	Values   []value
	Download bool
}

// client is a device or mail program the customer can pick on the setup page.
type client struct {
	Slug string
	Name string
	// HeadingPrefix precedes Name in the page heading, e.g. "Einrichten in" + "Outlook".
	HeadingPrefix string
	Summary       string
	Icon          string
	steps         func(profile.Account, profile.MailServer) []step
}

var clients = []client{
	{Slug: "iphone", Name: "iPhone und iPad", HeadingPrefix: "Einrichten auf", Summary: "Automatisch · 1 Minute", Icon: "phone", steps: iphoneSteps},
	{Slug: "mac", Name: "Mac", HeadingPrefix: "Einrichten auf dem", Summary: "Automatisch · 1 Minute", Icon: "laptop", steps: macSteps},
	{Slug: "outlook", Name: "Outlook", HeadingPrefix: "Einrichten in", Summary: "Schritt für Schritt · 3 Minuten", Icon: "mail", steps: outlookSteps},
	{Slug: "thunderbird", Name: "Thunderbird", HeadingPrefix: "Einrichten in", Summary: "Schritt für Schritt · 3 Minuten", Icon: "send", steps: thunderbirdSteps},
	{Slug: "android", Name: "Android", HeadingPrefix: "Einrichten auf", Summary: "Gmail-App · 3 Minuten", Icon: "android", steps: androidSteps},
}

func findClient(slug string) (client, bool) {
	for _, candidate := range clients {
		if candidate.Slug == slug {
			return candidate, true
		}
	}
	return client{}, false
}

// detectClient guesses the client matching the visitor's device, or "" if unknown. iPads
// identify as Macintosh by default; app.js corrects that case with touch information.
func detectClient(userAgent string) string {
	switch {
	case strings.Contains(userAgent, "iPhone"), strings.Contains(userAgent, "iPad"):
		return "iphone"
	case strings.Contains(userAgent, "Android"):
		return "android"
	case strings.Contains(userAgent, "Macintosh"):
		return "mac"
	case strings.Contains(userAgent, "Windows"):
		return "outlook"
	}
	return ""
}

const passwordHint = "Das Passwort deines Postfachs"

func smtpSecurity(server profile.MailServer) string {
	if server.SMTPPort == 465 {
		return "SSL/TLS"
	}
	return "STARTTLS"
}

// serverLabels are the field names a mail program uses in its server form. Fields with an
// empty label do not exist in that program.
type serverLabels struct {
	Server, Port, Security, Username string
}

func serverValues(labels serverLabels, host string, port int, security, username string) []value {
	values := []value{
		{Label: labels.Server, Value: host, Copy: true},
		{Label: labels.Port, Value: strconv.Itoa(port)},
		{Label: labels.Security, Value: security},
	}
	if labels.Username != "" {
		values = append(values, value{Label: labels.Username, Value: username, Copy: true})
	}
	return values
}

func incoming(labels serverLabels, account profile.Account, server profile.MailServer) []value {
	return serverValues(labels, server.IMAPHost, profile.IMAPPort, "SSL/TLS", account.Email)
}

func outgoing(labels serverLabels, account profile.Account, server profile.MailServer) []value {
	return serverValues(labels, server.SMTPHost, server.SMTPPort, smtpSecurity(server), account.Email)
}

// The wording of the steps follows the vendors' help pages: Apple (profile installation on
// iPhone, iPad and Mac), Microsoft (classic and new Outlook), Google (Gmail app) and, for
// Thunderbird, the mittwald FAQ.

func iphoneSteps(profile.Account, profile.MailServer) []step {
	return []step{
		{Title: "Profil laden", Download: true,
			Text: "Öffne diese Seite in Safari, lade das Profil und bestätige den Hinweis mit „Zulassen“."},
		{Title: "Profil öffnen",
			Text: "Öffne die App „Einstellungen“ und tippe oben auf „Profil geladen“. Das Profil steht dort nur wenige Minuten bereit – lade es sonst einfach noch einmal."},
		{Title: "Installieren",
			Text: "Tippe oben rechts auf „Installieren“ und gib das Passwort deines Postfachs ein. Deine E-Mails erscheinen danach in der Mail-App."},
	}
}

func macSteps(profile.Account, profile.MailServer) []step {
	return []step{
		{Title: "Profil laden", Download: true,
			Text: "Lade das Profil und öffne die Datei „email.mobileconfig“ aus deinen Downloads."},
		{Title: "Profil auswählen",
			Text: "Öffne die Systemeinstellungen und klicke auf „Allgemein“ und „Geräteverwaltung“. Doppelklicke im Bereich „Geladen“ auf das Profil."},
		{Title: "Installieren",
			Text: "Klicke auf „Installieren“ und gib das Passwort deines Postfachs ein. Deine E-Mails erscheinen danach in Mail."},
	}
}

func outlookSteps(account profile.Account, server profile.MailServer) []step {
	labels := serverLabels{Server: "Server", Port: "Port", Security: "Verschlüsselungsmethode"}
	steps := []step{
		{Title: "Konto hinzufügen",
			Text:   "Klicke in Outlook auf „Datei“ und „Konto hinzufügen“ und gib deine Adresse ein. Im neuen Outlook findest du „Konto hinzufügen“ unter „Ansicht“, „Ansichtseinstellungen“, „Konten“.",
			Values: []value{{Label: "E-Mail-Adresse", Value: account.Email, Copy: true}}},
		{Title: "Manuell einrichten",
			Text: "Klicke auf „Erweiterte Optionen“, setze den Haken bei „Ich möchte mein Konto manuell einrichten“ und klicke auf „Verbinden“. Wähle als Kontotyp „IMAP“."},
		{Title: "Eingehende E-Mail eintragen", Values: incoming(labels, account, server)},
		{Title: "Ausgehende E-Mail eintragen", Values: outgoing(labels, account, server)},
		{Title: "Anmelden",
			Text:   "Klicke auf „Weiter“, gib dein Kennwort ein und klicke auf „Verbinden“. Fragt Outlook nach einem Benutzernamen, ist das deine E-Mail-Adresse.",
			Values: []value{{Label: "Kennwort", Value: passwordHint}}},
	}
	if server.IMAPPathPrefix != "" {
		steps = append(steps, step{Title: "Ordner synchronisieren",
			Text:   "Öffne „Datei“ und „Kontoeinstellungen“, wähle das Postfach und klicke auf „Ändern“. Trage den Stammordnerpfad ein, damit alle Ordner synchronisiert werden.",
			Values: []value{{Label: "Stammordnerpfad", Value: server.IMAPPathPrefix, Copy: true}}})
	}
	return steps
}

func thunderbirdSteps(account profile.Account, server profile.MailServer) []step {
	labels := serverLabels{Server: "Hostname", Port: "Port", Security: "Verbindungssicherheit", Username: "Benutzername"}
	steps := []step{
		{Title: "Konto hinzufügen",
			Text: "Öffne in Thunderbird das Menü mit den drei Strichen und wähle „Neues Konto“ und „Bestehende E-Mail-Adresse“. Trage deine Daten ein.",
			Values: []value{
				{Label: "Name", Value: account.DisplayName, Copy: true},
				{Label: "E-Mail-Adresse", Value: account.Email, Copy: true},
				{Label: "Passwort", Value: passwordHint},
			}},
		{Title: "Manuell einrichten",
			Text: "Klicke auf „Manuell einrichten“, damit du die Server selbst eintragen kannst."},
		{Title: "Posteingangs-Server eintragen",
			Text:   "Wähle als Protokoll „IMAP“ und als Authentifizierungsmethode „Passwort, normal“.",
			Values: incoming(labels, account, server)},
		{Title: "Postausgangs-Server eintragen",
			Text:   "Wähle auch hier „Passwort, normal“ als Authentifizierungsmethode.",
			Values: outgoing(labels, account, server)},
		{Title: "Abschließen",
			Text: "Klicke auf „Erneut testen“ und danach auf „Fertig“. Thunderbird lädt jetzt deine E-Mails."},
	}
	if server.IMAPPathPrefix != "" {
		steps = append(steps, step{Title: "Ordner synchronisieren",
			Text:   "Öffne die „Konten-Einstellungen“ und dort die „Server-Einstellungen“. Klicke auf „Erweitert…“ und trage das IMAP-Server-Verzeichnis ein, damit alle Ordner synchronisiert werden.",
			Values: []value{{Label: "IMAP-Server-Verzeichnis", Value: server.IMAPPathPrefix, Copy: true}}})
	}
	return steps
}

func androidSteps(account profile.Account, server profile.MailServer) []step {
	labels := serverLabels{Server: "Server", Port: "Port", Security: "Sicherheitstyp", Username: "Nutzername"}
	return []step{
		{Title: "Konto hinzufügen",
			Text:   "Öffne die Gmail-App, tippe oben rechts auf dein Profilbild und wähle „Weiteres Konto hinzufügen“ und „Andere“. Gib deine Adresse ein und tippe auf „Weiter“.",
			Values: []value{{Label: "E-Mail-Adresse", Value: account.Email, Copy: true}}},
		{Title: "Kontotyp wählen",
			Text:   "Wähle „Privat (IMAP)“, gib dein Passwort ein und tippe auf „Weiter“.",
			Values: []value{{Label: "Passwort", Value: passwordHint}}},
		{Title: "Eingangsserver eintragen", Values: incoming(labels, account, server)},
		{Title: "Ausgangsserver eintragen",
			Text:   "Lass „Anmeldung erforderlich“ eingeschaltet.",
			Values: outgoing(labels, account, server)},
		{Title: "Abschließen",
			Text: "Bestätige die Kontooptionen mit „Weiter“. Deine E-Mails erscheinen danach in der Gmail-App."},
	}
}
