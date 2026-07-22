// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

// https://astro.build/config
export default defineConfig({
  site: "https://murk.interrupted.sh",
  integrations: [
    starlight({
      title: "murk",
      description:
        "Encrypted secrets manager for developers — one file, age encryption, git-friendly.",
      logo: {
        src: "./src/assets/murk-logo.svg",
        alt: "murk",
      },
      favicon: "/favicon.svg",
      customCss: ["./src/styles/brand.css"],
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/iicky/murk",
        },
      ],
      // murk docs are dark-only: no light theme, no theme toggle.
      components: {
        ThemeSelect: "./src/components/ThemeSelect.astro",
      },
      // Force the dark theme before paint and persist it, so a light system
      // preference (or a stale stored value) can't surface a light page now
      // that the toggle is gone.
      head: [
        {
          tag: "script",
          content:
            'document.documentElement.dataset.theme="dark";try{localStorage.setItem("starlight-theme","dark")}catch(e){}',
        },
      ],
      // IA per the docs-site epic. Content lives in src/content/docs/.
      sidebar: [
        { label: "Overview", link: "/" },
        { label: "Install & verify", link: "/install/" },
        { label: "Quick start", link: "/quick-start/" },
        {
          label: "Guides",
          items: [{ autogenerate: { directory: "guides" } }],
        },
        {
          label: "Concepts",
          items: [{ autogenerate: { directory: "concepts" } }],
        },
        {
          label: "Reference",
          items: [{ autogenerate: { directory: "reference" } }],
        },
        {
          label: "Security",
          items: [{ autogenerate: { directory: "security" } }],
        },
        {
          label: "Project",
          items: [
            { label: "Roadmap", link: "/roadmap/" },
            { label: "Changelog", link: "/changelog/" },
          ],
        },
      ],
    }),
  ],
});
