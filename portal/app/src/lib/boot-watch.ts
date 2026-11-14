// What a person sees when the dashboard cannot start at all (the server is gone, a script or the stylesheet does not load).
// The page's own scripts and styles are exactly what is missing then, so this is inline: one script, one style and one block
// of markup, each allowed by hash in the page policy (scripts/csp-hashes.mjs adds the hashes at build time). After
// BOOT_DEADLINE_MS without the dashboard reporting that it started, the block appears.

export const BOOT_DEADLINE_MS = 8000;

// The words of the state (rendered as ordinary elements by src/pages/_document.tsx; no markup string is injected).
export const BOOT_COPY = {
  title: "Can't reach ConsentVault",
  cause: 'The page did not finish loading. The service may be down, or your connection dropped.',
  next: 'Check your connection, then try again. Nothing was changed.',
  retry: 'Retry',
};

// The inline script and style are put into each built page by scripts/csp-hashes.mjs (not by the page's own code), at these
// placeholders, and allowed by hash in the policy.
export const BOOT_STYLE_SLOT = 'cv-boot-style';
export const BOOT_SCRIPT_SLOT = 'cv-boot-script';

export const BOOT_STYLE =
  '#boot-fail{max-width:30rem;margin:12vh auto 0;padding:1.5rem 1.75rem;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;color:#1d2a36;background:#fff;border:1px solid #d6dde4;border-left:4px solid #b4412c;border-radius:8px}' +
  '#boot-fail[hidden]{display:none}#boot-fail h1{margin:0 0 .75rem;font-size:1.35rem}#boot-fail p{margin:.4rem 0}' +
  '#boot-fail button{margin-top:1rem;padding:.55rem 1.1rem;font:inherit;font-weight:600;color:#fff;background:#2a3845;border:0;border-radius:6px;cursor:pointer}';

export const BOOT_SCRIPT =
  `(function(){setTimeout(function(){var d=document;if(d.documentElement.dataset.ready)return;var f=d.getElementById("boot-fail");if(!f)return;f.hidden=false;` +
  `var b=d.getElementById("boot-retry");if(b)b.addEventListener("click",function(){location.reload()})},${BOOT_DEADLINE_MS})})();`;
