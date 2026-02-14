const stage = process.env.SST_STAGE || "dev"

export default {
  url: stage === "production" ? "https://opensploit.ai" : `https://${stage}.opensploit.ai`,
  console: stage === "production" ? "https://opensploit.ai/auth" : `https://${stage}.opensploit.ai/auth`,
  github: "https://github.com/silicon-works/opensploit",
  headerLinks: [
    { name: "app.header.home", url: "/" },
    { name: "app.header.docs", url: "/docs/" },
  ],
}
