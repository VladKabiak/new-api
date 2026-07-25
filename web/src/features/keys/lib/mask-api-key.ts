/** Rendered in place of a key whose edges were too short to store. */
const OPAQUE_KEY_PLACEHOLDER = "*".repeat(18);

/**
 * Renders an API key for display from `key_prefix`, the only fragment the
 * server keeps once a key is hashed: its first and last four characters. A key
 * too short to fragment has no stored edges at all and gets a fixed
 * placeholder rather than exposing the little there is.
 */
export function maskApiKey(keyPrefix: string): string {
  if (keyPrefix.length < 8) return OPAQUE_KEY_PLACEHOLDER;
  return `sk-${keyPrefix.slice(0, 4)}**********${keyPrefix.slice(4)}`;
}
