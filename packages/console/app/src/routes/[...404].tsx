import "./[...404].css"
import { Title } from "@solidjs/meta"
import { HttpStatusCode } from "@solidjs/start"
import logoLight from "../asset/logo.svg"
import logoDark from "../asset/logo.svg"

export default function NotFound() {
  return (
    <main data-page="not-found">
      <Title>Not Found | opensploit</Title>
      <HttpStatusCode code={404} />
      <div data-component="content">
        <section data-component="top">
          <a href="/" data-slot="logo-link">
            <img data-slot="logo light" src={logoLight} alt="opensploit logo light" />
            <img data-slot="logo dark" src={logoDark} alt="opensploit logo dark" />
          </a>
          <h1 data-slot="title">404 - Page Not Found</h1>
        </section>

        <section data-component="actions">
          <div data-slot="action">
            <a href="/">Home</a>
          </div>
          <div data-slot="action">
            <a href="/docs">Docs</a>
          </div>
          <div data-slot="action">
            <a href="https://github.com/silicon-works/opensploit">GitHub</a>
          </div>
          <div data-slot="action">
            <a href="/discord">Discord</a>
          </div>
        </section>
      </div>
    </main>
  )
}
