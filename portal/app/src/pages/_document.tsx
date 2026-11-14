import { Html, Head, Main, NextScript } from 'next/document';
import { BOOT_COPY, BOOT_SCRIPT_SLOT, BOOT_STYLE_SLOT } from '../lib/boot-watch.ts';

// The boot state is plain elements. Its inline style and script are put into the built pages by scripts/csp-hashes.mjs at the
// two placeholders below (and allowed by hash in the policy); no HTML string is written from here.
export default function Document() {
  return (
    <Html lang="en">
      <Head>
        <meta name="theme-color" content="#2A3845" />
        <meta name="robots" content="noindex" />
        <meta name="referrer" content="no-referrer" />
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <meta name={BOOT_STYLE_SLOT} content="" />
      </Head>
      <body>
        <div id="boot-fail" role="alert" hidden>
          <h1>{BOOT_COPY.title}</h1>
          <p><b>Cause:</b> {BOOT_COPY.cause}</p>
          <p><b>Next:</b> {BOOT_COPY.next}</p>
          <button type="button" id="boot-retry">{BOOT_COPY.retry}</button>
        </div>
        <meta name={BOOT_SCRIPT_SLOT} content="" />
        <Main />
        <NextScript />
      </body>
    </Html>
  );
}
