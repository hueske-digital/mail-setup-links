// Package profile builds Apple configuration profiles for a mail account.
package profile

import (
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"howett.net/plist"
)

// IMAPPort is fixed: profiles only use IMAP over implicit TLS.
const IMAPPort = 993

// Field names reported by Account.Validate.
const (
	FieldEmail       = "email"
	FieldDisplayName = "displayName"
)

var uuidNamespace = uuid.MustParse("6f1d1c0e-7a52-4b7e-9d0b-3c1f1f0e8a11")

// Account is the per-customer part of a profile. It never contains a password. The e-mail
// address is also the login name.
type Account struct {
	Email       string `json:"e"`
	DisplayName string `json:"n"`
}

// MailServer is the server every profile points to. It is configuration, never link input.
type MailServer struct {
	IMAPHost string
	SMTPHost string
	SMTPPort int
	// IMAPPathPrefix is the folder under which the server keeps all mail folders, e.g.
	// "INBOX". Empty if the server needs none.
	IMAPPathPrefix string
}

// Options carries the issuer details shown in the profile.
type Options struct {
	OrgName  string
	IDPrefix string
}

func validText(value string, maxRunes int) bool {
	if value == "" || value != strings.TrimSpace(value) || utf8.RuneCountInString(value) > maxRunes {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}

func validEmail(value string) bool {
	if !validText(value, 254) {
		return false
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value {
		return false
	}
	at := strings.LastIndexByte(value, '@')
	return strings.Contains(value[at+1:], ".")
}

// Validate returns the names of all invalid fields.
func (a Account) Validate() []string {
	var invalid []string
	if !validEmail(a.Email) {
		invalid = append(invalid, FieldEmail)
	}
	if !validText(a.DisplayName, 100) {
		invalid = append(invalid, FieldDisplayName)
	}
	return invalid
}

type mailPayload struct {
	PayloadType        string
	PayloadVersion     int
	PayloadIdentifier  string
	PayloadUUID        string
	PayloadDisplayName string

	EmailAccountDescription string
	EmailAccountName        string
	EmailAccountType        string
	EmailAddress            string

	IncomingMailServerAuthentication string
	IncomingMailServerHostName       string
	IncomingMailServerPortNumber     int
	IncomingMailServerUseSSL         bool
	IncomingMailServerUsername       string
	IncomingMailServerIMAPPathPrefix string `plist:",omitempty"`

	OutgoingMailServerAuthentication       string
	OutgoingMailServerHostName             string
	OutgoingMailServerPortNumber           int
	OutgoingMailServerUseSSL               bool
	OutgoingMailServerUsername             string
	OutgoingPasswordSameAsIncomingPassword bool
}

type configuration struct {
	PayloadContent      []mailPayload
	PayloadDisplayName  string
	PayloadDescription  string
	PayloadIdentifier   string
	PayloadOrganization string
	PayloadType         string
	PayloadUUID         string
	PayloadVersion      int
}

// Build returns an unsigned XML configuration profile with one IMAP/SMTP mail payload.
// UUIDs are derived from the address, so installing a profile again replaces the previous one.
func Build(account Account, server MailServer, options Options) ([]byte, error) {
	profileUUID := strings.ToUpper(uuid.NewSHA1(uuidNamespace, []byte("profile:"+account.Email)).String())
	mailUUID := strings.ToUpper(uuid.NewSHA1(uuidNamespace, []byte("mail:"+account.Email)).String())

	return plist.MarshalIndent(configuration{
		PayloadContent: []mailPayload{{
			PayloadType:        "com.apple.mail.managed",
			PayloadVersion:     1,
			PayloadIdentifier:  options.IDPrefix + ".mail." + mailUUID,
			PayloadUUID:        mailUUID,
			PayloadDisplayName: account.Email,

			EmailAccountDescription: account.Email,
			EmailAccountName:        account.DisplayName,
			EmailAccountType:        "EmailTypeIMAP",
			EmailAddress:            account.Email,

			IncomingMailServerAuthentication: "EmailAuthPassword",
			IncomingMailServerHostName:       server.IMAPHost,
			IncomingMailServerPortNumber:     IMAPPort,
			IncomingMailServerUseSSL:         true,
			IncomingMailServerUsername:       account.Email,
			IncomingMailServerIMAPPathPrefix: server.IMAPPathPrefix,

			OutgoingMailServerAuthentication:       "EmailAuthPassword",
			OutgoingMailServerHostName:             server.SMTPHost,
			OutgoingMailServerPortNumber:           server.SMTPPort,
			OutgoingMailServerUseSSL:               true,
			OutgoingMailServerUsername:             account.Email,
			OutgoingPasswordSameAsIncomingPassword: true,
		}},
		PayloadDisplayName:  "E-Mail " + account.Email,
		PayloadDescription:  "Richtet das E-Mail-Konto " + account.Email + " ein.",
		PayloadIdentifier:   options.IDPrefix + "." + profileUUID,
		PayloadOrganization: options.OrgName,
		PayloadType:         "Configuration",
		PayloadUUID:         profileUUID,
		PayloadVersion:      1,
	}, plist.XMLFormat, "\t")
}
