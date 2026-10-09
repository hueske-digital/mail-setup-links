package profile

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"howett.net/plist"
)

var (
	testServer  = MailServer{IMAPHost: "mail.example.net", SMTPHost: "smtp.example.net", SMTPPort: 587}
	testOptions = Options{OrgName: "Example GmbH", IDPrefix: "net.example.setup"}
)

func TestBuild(t *testing.T) {
	account := Account{Email: "kunde@example.com", DisplayName: `Müller & <Söhne> "GmbH"`}
	data, err := Build(account, testServer, testOptions)
	if err != nil {
		t.Fatal(err)
	}

	var got configuration
	if _, err := plist.Unmarshal(data, &got); err != nil {
		t.Fatalf("profile is not a valid plist: %v", err)
	}
	if got.PayloadType != "Configuration" || got.PayloadOrganization != "Example GmbH" {
		t.Errorf("unexpected envelope: %+v", got)
	}
	if len(got.PayloadContent) != 1 {
		t.Fatalf("got %d payloads, want 1", len(got.PayloadContent))
	}
	payload := got.PayloadContent[0]
	want := mailPayload{
		PayloadType:        "com.apple.mail.managed",
		PayloadVersion:     1,
		PayloadIdentifier:  payload.PayloadIdentifier,
		PayloadUUID:        payload.PayloadUUID,
		PayloadDisplayName: "kunde@example.com",

		EmailAccountDescription: "kunde@example.com",
		EmailAccountName:        `Müller & <Söhne> "GmbH"`,
		EmailAccountType:        "EmailTypeIMAP",
		EmailAddress:            "kunde@example.com",

		IncomingMailServerAuthentication: "EmailAuthPassword",
		IncomingMailServerHostName:       "mail.example.net",
		IncomingMailServerPortNumber:     993,
		IncomingMailServerUseSSL:         true,
		IncomingMailServerUsername:       "kunde@example.com",

		OutgoingMailServerAuthentication:       "EmailAuthPassword",
		OutgoingMailServerHostName:             "smtp.example.net",
		OutgoingMailServerPortNumber:           587,
		OutgoingMailServerUseSSL:               true,
		OutgoingMailServerUsername:             "kunde@example.com",
		OutgoingPasswordSameAsIncomingPassword: true,
	}
	if payload != want {
		t.Errorf("payload mismatch:\n got %+v\nwant %+v", payload, want)
	}
	if !strings.HasPrefix(payload.PayloadIdentifier, "net.example.setup.mail.") {
		t.Errorf("unexpected identifier %q", payload.PayloadIdentifier)
	}
	if bytes.Contains(data, []byte("IMAPPathPrefix")) {
		t.Error("profile sets a path prefix although none is configured")
	}
	if bytes.Contains(data, []byte("Password</key>\n\t\t\t<string>")) {
		t.Error("profile must not contain a password")
	}
}

func TestBuildSetsIMAPPathPrefix(t *testing.T) {
	server := testServer
	server.IMAPPathPrefix = "INBOX"
	data, err := Build(Account{Email: "a@example.com", DisplayName: "A"}, server, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	var got configuration
	if _, err := plist.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if prefix := got.PayloadContent[0].IncomingMailServerIMAPPathPrefix; prefix != "INBOX" {
		t.Errorf("path prefix = %q, want INBOX", prefix)
	}
}

func TestBuildIsStablePerAddress(t *testing.T) {
	first, err := Build(Account{Email: "a@example.com", DisplayName: "A"}, testServer, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Build(Account{Email: "a@example.com", DisplayName: "A"}, testServer, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Build(Account{Email: "b@example.com", DisplayName: "A"}, testServer, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, again) {
		t.Error("same address must produce the same profile")
	}
	var a, b configuration
	if _, err := plist.Unmarshal(first, &a); err != nil {
		t.Fatal(err)
	}
	if _, err := plist.Unmarshal(other, &b); err != nil {
		t.Fatal(err)
	}
	if a.PayloadUUID == b.PayloadUUID {
		t.Error("different addresses must produce different UUIDs")
	}
}

func TestValidate(t *testing.T) {
	valid := Account{Email: "kunde@example.com", DisplayName: "Max Mustermann"}
	cases := map[string]struct {
		mutate func(*Account)
		want   []string
	}{
		"valid":                 {func(*Account) {}, nil},
		"email without domain":  {func(a *Account) { a.Email = "kunde" }, []string{FieldEmail}},
		"email without tld":     {func(a *Account) { a.Email = "kunde@localhost" }, []string{FieldEmail}},
		"email with name":       {func(a *Account) { a.Email = "Max <kunde@example.com>" }, []string{FieldEmail}},
		"email too long":        {func(a *Account) { a.Email = strings.Repeat("a", 250) + "@example.com" }, []string{FieldEmail}},
		"empty display name":    {func(a *Account) { a.DisplayName = "" }, []string{FieldDisplayName}},
		"display name too long": {func(a *Account) { a.DisplayName = strings.Repeat("ä", 101) }, []string{FieldDisplayName}},
		"control character":     {func(a *Account) { a.DisplayName = "Max\nMustermann" }, []string{FieldDisplayName}},
		"everything empty":      {func(a *Account) { *a = Account{} }, []string{FieldEmail, FieldDisplayName}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			account := valid
			tc.mutate(&account)
			if got := account.Validate(); !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
