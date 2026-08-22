/**
 * Reads a user-agent string well enough to tell two devices apart.
 *
 * Deliberately rough. The question being answered is "which of these is my
 * laptop", not "what browser is this" — and a confidently wrong label is worse
 * than a vague one, so anything unrecognised stays unrecognised.
 */
export function describeDevice(userAgent) {
  if (!userAgent) return "Unknown device";

  const platform = /Windows/i.test(userAgent)
    ? "Windows"
    : /Macintosh|Mac OS/i.test(userAgent)
      ? "macOS"
      : /Android/i.test(userAgent)
        ? "Android"
        : /iPhone|iPad/i.test(userAgent)
          ? "iOS"
          : /Linux/i.test(userAgent)
            ? "Linux"
            : null;

  // Order matters: Edge and Opera both claim to be Chrome, and Chrome claims
  // to be Safari. Checking the specific ones first is the only way to get an
  // answer that is not "Safari" for almost everybody.
  const browser = /curl\//i.test(userAgent)
    ? "curl"
    : /Edg\//i.test(userAgent)
      ? "Edge"
      : /OPR\//i.test(userAgent)
        ? "Opera"
        : /Chrome\//i.test(userAgent)
          ? "Chrome"
          : /Firefox\//i.test(userAgent)
            ? "Firefox"
            : /Safari\//i.test(userAgent)
              ? "Safari"
              : null;

  if (platform && browser) return browser + " on " + platform;
  return platform || browser || "Unknown device";
}
