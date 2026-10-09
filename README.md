# mail-setup-links

Generates prefilled links that set up an e-mail account. A customer opens the link, picks a device
or mail program and either downloads a signed Apple configuration profile (iPhone, iPad, Mac)
or follows personalised steps (Outlook, Thunderbird, Android). Profiles never contain a password; the device asks for it
during installation.

## How it works

- `GET /` is a public form: e-mail address and display name. The address is also the login
  name.
- `POST /links` returns a link `/e/<token>`. The token is the form data plus an expiry time,
  encrypted and authenticated with AES-256-GCM (`LINK_SECRET`). Nothing is stored server side.
- `GET /e/<token>` lets the customer pick a device or mail program; the one matching the
  visitor's device is listed first. `GET /e/<token>/<client>` shows personalised steps for
  `iphone`, `mac`, `outlook`, `thunderbird` or `android`, `GET /e/<token>/email.mobileconfig`
  delivers the profile.
- The mail server is configuration (`MAIL_IMAP_HOST`, `MAIL_SMTP_HOST`). It cannot be set
  through the form or a link, so the service cannot be used to sign profiles pointing to
  foreign servers.
- With `SIGNING_MODE=acme` the service obtains a certificate for the host name of
  `PUBLIC_URL` via ACME HTTP-01 (Let's Encrypt by default), renews it after two thirds of its
  lifetime and signs every profile with it. Without a valid certificate the profile download
  answers `503` instead of delivering an unsigned profile.

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PUBLIC_URL` | yes | | Public origin, e.g. `https://setup.example.com`. Requests for other hosts are rejected. |
| `LINK_SECRET` | yes | | 32 random bytes, base64 (`openssl rand -base64 32`). Changing it invalidates all links. |
| `MAIL_IMAP_HOST` | yes | | IMAP server (port 993, TLS). |
| `MAIL_SMTP_HOST` | yes | | SMTP server. |
| `MAIL_SMTP_PORT` | no | `465` | `465` (TLS, shown as "SSL/TLS" like IMAP) or `587` (shown as "STARTTLS"). |
| `MAIL_IMAP_PATH_PREFIX` | no | | IMAP folder prefix the server requires, e.g. `INBOX`. Set in the profile and shown as an extra step for Outlook and Thunderbird. |
| `ORG_NAME` | yes | | Shown on the pages and as organization in the profile. |
| `WEBMAIL_URL` | no | | Webmail choice on the setup page; hidden when empty. `{email}` is replaced, e.g. `https://webmail.example.net/?_user={email}` prefills a Roundcube login. |
| `LINK_TTL_DAYS` | no | `30` | Lifetime of a link, 1–365. |
| `PROFILE_ID_PREFIX` | no | reversed host of `PUBLIC_URL` | Reverse DNS prefix of the profile identifiers. |
| `HOST`, `PORT` | no | `0.0.0.0`, `3000` | Listen address. |
| `TRUST_PROXY` | no | `false` | Set to `true` behind exactly one reverse proxy: `X-Forwarded-For` and `X-Forwarded-Host` are then trusted. |
| `SIGNING_MODE` | no | `off` | `off` delivers unsigned profiles, `acme` signs them. |
| `ACME_EMAIL` | with `acme` | | Contact address of the ACME account. |
| `ACME_TOS_AGREED` | with `acme` | `false` | Must be `true`: accepts the ACME provider's terms of service. |
| `ACME_DIRECTORY_URL` | no | Let's Encrypt production | ACME directory. |
| `DATA_DIR` | no | `./data` (`/data` in the image) | ACME account key and signing certificate. |

## Operation

- Requests are limited per client and minute: 10 for `POST /links`, 120 for every other page.
  The form body is limited to 8 KiB.
- For signing, `http://<host of PUBLIC_URL>/.well-known/acme-challenge/…` must reach the
  service on port 80 from the internet. A proxy that answers this path itself prevents
  issuance.
- Run one instance only: pending ACME challenges and rate limits are kept in memory.
- Mount a volume at `/data`, otherwise every restart requests a new certificate.
- Logs contain the route pattern, status and duration of each request, no addresses or tokens.

## Development

Tools are pinned in `mise.toml` (`mise install`).

```sh
mise run lint       # gofmt and golangci-lint
mise run test       # unit and HTTP tests
mise run build      # binary in dist/
mise run test:acme  # end-to-end signing test in containers, see below
```

Run locally without signing:

```sh
PUBLIC_URL=http://localhost:3000 LINK_SECRET="$(openssl rand -base64 32)" \
  MAIL_IMAP_HOST=mail.example.net MAIL_SMTP_HOST=mail.example.net ORG_NAME="Example GmbH" \
  go run .
```

`mise run test:acme` starts the service and [Pebble](https://github.com/letsencrypt/pebble), a
test ACME server, with `compose.yaml`. It creates a link, waits for the certificate, downloads
the profile and verifies its signature against Pebble's root certificate with OpenSSL.

## Design and fonts

The pages use the colours, type scale and components of hueske.digital. The embedded fonts
Mona Sans and DM Serif Display are licensed under the SIL Open Font License 1.1.
