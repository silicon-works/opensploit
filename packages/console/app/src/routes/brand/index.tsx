import "./index.css"
import { Title, Meta, Link } from "@solidjs/meta"
import { Header } from "~/component/header"
import { config } from "~/config"
import { Footer } from "~/component/footer"
import { Legal } from "~/component/legal"
import previewLogoLight from "../../asset/brand/preview-opensploit-logo-light.png"
import previewLogoDark from "../../asset/brand/preview-opensploit-logo-dark.png"
import previewWordmarkLight from "../../asset/brand/preview-opensploit-wordmark-light.png"
import previewWordmarkDark from "../../asset/brand/preview-opensploit-wordmark-dark.png"
import previewWordmarkSimpleLight from "../../asset/brand/preview-opensploit-wordmark-simple-light.png"
import previewWordmarkSimpleDark from "../../asset/brand/preview-opensploit-wordmark-simple-dark.png"
import logoLightPng from "../../asset/brand/opensploit-logo-light.png"
import logoDarkPng from "../../asset/brand/opensploit-logo-dark.png"
import wordmarkLightPng from "../../asset/brand/opensploit-wordmark-light.png"
import wordmarkDarkPng from "../../asset/brand/opensploit-wordmark-dark.png"
import wordmarkSimpleLightPng from "../../asset/brand/opensploit-wordmark-simple-light.png"
import wordmarkSimpleDarkPng from "../../asset/brand/opensploit-wordmark-simple-dark.png"
import logoLightSvg from "../../asset/brand/opensploit-logo-light.svg"
import logoDarkSvg from "../../asset/brand/opensploit-logo-dark.svg"
import wordmarkLightSvg from "../../asset/brand/opensploit-wordmark-light.svg"
import wordmarkDarkSvg from "../../asset/brand/opensploit-wordmark-dark.svg"
import wordmarkSimpleLightSvg from "../../asset/brand/opensploit-wordmark-simple-light.svg"
import wordmarkSimpleDarkSvg from "../../asset/brand/opensploit-wordmark-simple-dark.svg"
const brandAssets = "/opensploit-brand-assets.zip"

export default function Brand() {
  const downloadFile = async (url: string, filename: string) => {
    try {
      const response = await fetch(url)
      const blob = await response.blob()
      const blobUrl = window.URL.createObjectURL(blob)

      const link = document.createElement("a")
      link.href = blobUrl
      link.download = filename
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)

      window.URL.revokeObjectURL(blobUrl)
    } catch (error) {
      console.error("Download failed:", error)
      const link = document.createElement("a")
      link.href = url
      link.target = "_blank"
      link.rel = "noopener noreferrer"
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
    }
  }

  return (
    <main data-page="enterprise">
      <Title>OpenSploit | Brand</Title>
      <Link rel="canonical" href={`${config.baseUrl}/brand`} />
      <Meta name="description" content="OpenSploit brand guidelines" />
      <div data-component="container">
        <Header />

        <div data-component="content">
          <section data-component="brand-content">
            <h1>Brand guidelines</h1>
            <p>Resources and assets to help you work with the OpenSploit brand.</p>
            <button
              data-component="download-button"
              onClick={() => downloadFile(brandAssets, "opensploit-brand-assets.zip")}
            >
              Download all assets
              <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path
                  d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="square"
                />
              </svg>
            </button>

            <div data-component="brand-grid">
              <div>
                <img src={previewLogoLight} alt="OpenSploit brand guidelines" />
                <div data-component="actions">
                  <button onClick={() => downloadFile(logoLightPng, "opensploit-logo-light.png")}>
                    PNG
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path
                        d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="square"
                      />
                    </svg>
                  </button>
                  <button onClick={() => downloadFile(logoLightSvg, "opensploit-logo.svg")}>
                    SVG
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path
                        d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="square"
                      />
                    </svg>
                  </button>
                </div>
              </div>
              <div>
                <img src={previewLogoDark} alt="OpenSploit brand guidelines" />
                <div data-component="actions">
                  <button onClick={() => downloadFile(logoDarkPng, "opensploit-logo-dark.png")}>
                    PNG
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path
                        d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="square"
                      />
                    </svg>
                  </button>
                  <button onClick={() => downloadFile(logoDarkSvg, "opensploit-logo.svg")}>
                    SVG
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path
                        d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="square"
                      />
                    </svg>
                  </button>
                </div>
              </div>
              <div>
                <img src={previewWordmarkLight} alt="OpenSploit brand guidelines" />
                <div data-component="actions">
                  <button onClick={() => downloadFile(wordmarkLightPng, "opensploit-wordmark-light.png")}>
                    PNG
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path
                        d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="square"
                      />
                    </svg>
                  </button>
                  <button onClick={() => downloadFile(wordmarkLightSvg, "opensploit-wordmark-light.svg")}>
                    SVG
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path
                        d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="square"
                      />
                    </svg>
                  </button>
                </div>
              </div>
              <div>
                <img src={previewWordmarkDark} alt="OpenSploit brand guidelines" />
                <div data-component="actions">
                  <button onClick={() => downloadFile(wordmarkDarkPng, "opensploit-wordmark-dark.png")}>
                    PNG
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path
                        d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="square"
                      />
                    </svg>
                  </button>
                  <button onClick={() => downloadFile(wordmarkDarkSvg, "opensploit-wordmark-dark.svg")}>
                    SVG
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path
                        d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="square"
                      />
                    </svg>
                  </button>
                </div>
              </div>
              <div>
                <img src={previewWordmarkSimpleLight} alt="OpenSploit brand guidelines" />
                <div data-component="actions">
                  <button onClick={() => downloadFile(wordmarkSimpleLightPng, "opensploit-wordmark-simple-light.png")}>
                    PNG
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path
                        d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="square"
                      />
                    </svg>
                  </button>
                  <button onClick={() => downloadFile(wordmarkSimpleLightSvg, "opensploit-wordmark-simple-light.svg")}>
                    SVG
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path
                        d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="square"
                      />
                    </svg>
                  </button>
                </div>
              </div>
              <div>
                <img src={previewWordmarkSimpleDark} alt="OpenSploit brand guidelines" />
                <div data-component="actions">
                  <button onClick={() => downloadFile(wordmarkSimpleDarkPng, "opensploit-wordmark-simple-dark.png")}>
                    PNG
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path
                        d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="square"
                      />
                    </svg>
                  </button>
                  <button onClick={() => downloadFile(wordmarkSimpleDarkSvg, "opensploit-wordmark-simple-dark.svg")}>
                    SVG
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path
                        d="M13.9583 10.6247L10 14.583L6.04167 10.6247M10 2.08301V13.958M16.25 17.9163H3.75"
                        stroke="currentColor"
                        stroke-width="1.5"
                        stroke-linecap="square"
                      />
                    </svg>
                  </button>
                </div>
              </div>
            </div>
          </section>
        </div>
        <Footer />
      </div>
      <Legal />
    </main>
  )
}
