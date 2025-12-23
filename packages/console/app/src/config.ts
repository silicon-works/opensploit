/**
 * Application-wide constants and configuration
 */
export const config = {
  // Base URL
  baseUrl: "https://opensploit.ai",

  // GitHub
  github: {
    repoUrl: "https://github.com/silicon-works/opensploit",
    starsFormatted: {
      compact: "41K",
      full: "41,000",
    },
  },

  // Social links
  social: {
    twitter: "https://x.com/opensploit",
    discord: "https://discord.gg/opensploit",
  },

  // Static stats (used on landing page)
  stats: {
    contributors: "450",
    commits: "6,000",
    monthlyUsers: "400,000",
  },
} as const
