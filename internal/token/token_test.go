package token

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type payload struct {
	Email string `json:"e"`
}

func newCodec(t *testing.T, fill byte) *Codec {
	t.Helper()
	codec, err := New(bytes.Repeat([]byte{fill}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func TestRoundTrip(t *testing.T) {
	codec := newCodec(t, 1)
	sealed, err := codec.Seal(payload{Email: "kunde@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "kunde") {
		t.Fatal("token exposes the payload")
	}
	var got payload
	if err := codec.Open(sealed, &got); err != nil {
		t.Fatal(err)
	}
	if got.Email != "kunde@example.com" {
		t.Fatalf("got %q", got.Email)
	}
}

func TestOpenRejects(t *testing.T) {
	codec := newCodec(t, 1)
	sealed, err := codec.Seal(payload{Email: "kunde@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	flipped := []byte(sealed)
	if flipped[len(flipped)-1] == 'A' {
		flipped[len(flipped)-1] = 'B'
	} else {
		flipped[len(flipped)-1] = 'A'
	}

	cases := map[string]struct {
		codec *Codec
		token string
	}{
		"tampered":      {codec, string(flipped)},
		"other key":     {newCodec(t, 2), sealed},
		"truncated":     {codec, sealed[:10]},
		"not base64url": {codec, "%%%"},
		"empty":         {codec, ""},
		"too long":      {codec, strings.Repeat("A", maxLength+1)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var got payload
			if err := tc.codec.Open(tc.token, &got); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestSealRejectsPayloadsThatWouldNotOpen(t *testing.T) {
	codec := newCodec(t, 1)
	if _, err := codec.Seal(payload{Email: strings.Repeat("a", maxLength)}); !errors.Is(err, ErrTooLong) {
		t.Fatalf("got %v, want ErrTooLong", err)
	}
}

func TestSealDoesNotInflateMarkupCharacters(t *testing.T) {
	codec := newCodec(t, 1)
	plain, err := codec.Seal(payload{Email: strings.Repeat("a", 300)})
	if err != nil {
		t.Fatal(err)
	}
	markup, err := codec.Seal(payload{Email: strings.Repeat("&", 300)})
	if err != nil {
		t.Fatal(err)
	}
	if len(markup) != len(plain) {
		t.Errorf("token grew from %d to %d characters", len(plain), len(markup))
	}
	var got payload
	if err := codec.Open(markup, &got); err != nil || got.Email != strings.Repeat("&", 300) {
		t.Errorf("round trip failed: %v", err)
	}
}

func TestNewRejectsShortKey(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("expected an error")
	}
}
