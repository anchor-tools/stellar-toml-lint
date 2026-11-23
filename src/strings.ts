/**
 * Small string helpers shared across modules.
 */

/**
 * Removes trailing `/` characters in linear time.
 *
 * `value.replace(/\/+$/, '')` looks equivalent, but on input with many
 * slashes that are not at the end (`a////…//b`) the regex engine retries the
 * run from every position, which is quadratic — a ReDoS vector when the value
 * comes from a remote document.
 */
export function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47 /* '/' */) end--;
  return end === value.length ? value : value.slice(0, end);
}
