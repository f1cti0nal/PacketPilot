import landingHtml from "./landing.html?raw";

// The marketing landing page is static, self-contained, trusted markup (no user input):
// one scoped `.pp-landing` fragment with its own <style> and inline SVG. Injecting it
// directly avoids a brittle ~1800-line HTML->JSX rewrite and keeps the design byte-for-byte
// what the design panel produced. Every CTA is a plain <a href="/app"> that does a full
// navigation, so no client-side router is needed here.
export function Landing() {
  return <div dangerouslySetInnerHTML={{ __html: landingHtml }} />;
}

export default Landing;
