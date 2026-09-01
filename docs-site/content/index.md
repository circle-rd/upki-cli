---
seo:
  title: uPKI CLI
  description: µPKI command-line client — enroll, renew, and manage X.509 certificates against a private ACME v2 Registration Authority.
---

:::u-page-hero
#title
uPKI CLI

#description
The Python client for the µPKI private PKI stack. Enroll and renew EC P-256 certificates, manage CRL downloads, and install certificates directly into browser trust stores — all against your own private ACME v2 Registration Authority.

#links
::::u-button{to="/docs/getting-started/introduction" size="xl" trailing-icon="i-lucide-arrow-right"}
Get started
::::

::::u-button{to="https://github.com/circle-rd/upki-cli" target="_blank" size="xl" variant="outline" icon="i-simple-icons-github"}
GitHub
::::
:::

:::u-page-section
#features
::::u-page-feature{icon="i-lucide-key-round" title="ACME v2 enrollment" description="Issues EC P-256 certificates via RFC 8555 ACME against any µPKI-RA instance — no internet, no Let's Encrypt required."}
::::

::::u-page-feature{icon="i-lucide-refresh-cw" title="Automatic renewal" description="A systemd service and timer renew every registered certificate daily, with a randomised delay to avoid thundering-herd."}
::::

::::u-page-feature{icon="i-lucide-globe" title="Browser integration" description="Installs certificates and the private CA directly into Firefox (NSS) and Chrome (NSS / macOS Keychain) with a single flag."}
::::

::::u-page-feature{icon="i-lucide-file-key" title="PEM and PKCS#12" description="Writes the node private key, PEM bundle, and optionally a password-protected PKCS#12 file for applications that require it."}
::::

::::u-page-feature{icon="i-lucide-shield" title="Private CA trust" description="Downloads and pins the CA certificate on first run. Any change to the CA cert prompts explicit confirmation before overwriting."}
::::

::::u-page-feature{icon="i-lucide-list" title="Local registry" description="Tracks all enrolled certificates in a local JSON registry, enabling batch renewal and safe deletion of associated key material."}
::::
:::
