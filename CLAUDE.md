# mail-setup-links

Go service, no framework. Commands: `mise run lint`, `mise run test`, `mise run build`,
`mise run test:acme` (containers, needs Docker). See `README.md` for behaviour and
configuration.

## Learnings from reviews

- Whatever `token.Codec.Seal` accepts must open again: keep form validation limits and the
  token length limit aligned, and test the longest accepted input end to end.
- State on disk belongs to the configuration that produced it. The signing certificate is
  stored under a name derived from ACME directory and hostname; do the same for new state.
- Reveal JavaScript-only controls only after feature detection. `navigator.clipboard` does
  not exist on plain-HTTP origins other than localhost.
- User-agent detection is a hint: iPads identify as Macintosh. `app.js` corrects the
  recommendation with touch information.
- CSS overrides in media queries go after the base rule and are scoped to the component
  they are meant for (`.steps .values`, not `.values`).
- ACME: finalize with `CreateCertFromOrder`; Pebble sends no `Location` header on finalize,
  which breaks `CreateOrderCert`.
- UI texts address the customer informally ("du"). The login name is always the e-mail
  address.
