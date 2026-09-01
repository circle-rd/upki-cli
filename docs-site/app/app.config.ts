export default defineAppConfig({
  docus: {
    title: "uPKI CLI",
    description: "µPKI command-line client — enroll, renew, and manage X.509 certificates against a private ACME v2 Registration Authority.",
    url: "https://docs.circle-cyber.com/upki-cli",
    image: "/social-card.png",
    socials: {
      github: "circle-rd/upki-cli",
    },
    github: {
      dir: "docs-site/content",
      branch: "main",
      repo: "upki-cli",
      owner: "circle-rd",
      edit: true,
    },
    aside: {
      level: 0,
      collapsed: false,
      exclude: [],
    },
    main: {
      padded: true,
      fluid: false,
    },
    header: {
      logo: false,
      showLinkIcon: true,
      exclude: [],
      fluid: false,
    },
    footer: {
      credits: {
        icon: "i-lucide-shield",
        text: "CIRCLE Cyber",
        href: "https://circle-cyber.com",
      },
      textLinks: [],
      iconLinks: [],
    },
  },
});
