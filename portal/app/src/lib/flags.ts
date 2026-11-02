// Feature flags named for the contract gap they wait on (design/handoff.md, endpoint rule).
// A gap element renders its "Not available" state until the contract lands and the flag flips.
export const FLAGS = {
  // The Capture Worker's site-key header is not named in contracts/capture.md.
  gap_site_key_header: false,
} as const;
