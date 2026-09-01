export default defineNuxtConfig({
  extends: ["docus"],
  app: {
    baseURL: process.env.NUXT_APP_BASE_URL ?? "/upki-cli/",
  },
  site: {
    url: process.env.NUXT_SITE_URL ?? "https://docs.circle-cyber.com/upki-cli",
  },
  llms: {
    title: "uPKI CLI",
    description: "µPKI command-line client — enroll, renew, and manage X.509 certificates against a private ACME v2 Registration Authority.",
    full: {
      title: "uPKI CLI — Complete Documentation",
      description: "uPKI CLI is the Python client for the µPKI private PKI stack. It interacts with a µPKI-RA Registration Authority via ACME v2 (RFC 8555) to enroll EC P-256 certificates, automate renewal through systemd timers, and install certificates into browser NSS databases.",
    },
  },
});
