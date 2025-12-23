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
      compact: "38K",
      full: "38,000",
    },
  },

  // Social links
  social: {
    twitter: "https://x.com/opensploit",
    discord: "https://discord.gg/opensploit",
  },

  // Static stats (used on landing page)
  stats: {
    contributors: "400",
    commits: "5,000",
    monthlyUsers: "400,000",
  },
} as const
