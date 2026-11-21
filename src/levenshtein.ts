/**
 * Shared typo-suggestion arithmetic.
 *
 * `src/presets.ts` and the orphaned-key scanner both answer "did the author
 * mean one of these?", and the answer has to be the same in both places: one
 * edit is always a typo, and beyond that the name has to be long enough for the
 * distance to mean something. Keeping the threshold in one function is what
 * stops a suggestion engine from being confident in one command and silent in
 * another.
 */

/**
 * Levenshtein distance, over the whole string.
 *
 * Row-at-a-time, so the cost is proportional to the shorter string.
 */
export function editDistance(a: string, b: string): number {
  const row = (length: number): number[] => Array.from({ length: length + 1 }, (_, i) => i);
  let previous = row(b.length);

  for (let i = 1; i <= a.length; i++) {
    const current = row(b.length);
    current[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const substitution = (previous[j - 1] ?? i) + (a[i - 1] === b[j - 1] ? 0 : 1);
      current[j] = Math.min(substitution, (previous[j] ?? i) + 1, (current[j - 1] ?? j) + 1);
    }
    previous = current;
  }

  return previous[b.length] ?? Math.max(a.length, b.length);
}

/**
 * How far a candidate may be before it stops counting as the same word.
 *
 * One edit is always a typo. Beyond that, only for a name long enough for the
 * distance to be meaningful — a two-character name is one edit away from
 * everything, so a threshold that scales with length is what keeps `I` from
 * being "suggested" as a typo of `ORG_URL`.
 */
export function typoThreshold(name: string): number {
  return Math.max(1, Math.floor(name.length / 3));
}

/**
 * The candidate closest to `name`, or `undefined` when nothing is near enough.
 *
 * Case is folded for the comparison, because `public_key` and `PUBLIC_KEY` are
 * the same field written twice. Ties go to whichever candidate the caller lists
 * first, which is the order that reads as the canonical spelling.
 */
export function nearestMatch<T extends string>(
  candidates: Iterable<T>,
  name: string,
  threshold = typoThreshold(name),
): T | undefined {
  const needle = name.toLowerCase();
  let nearest: T | undefined;
  let smallest = Number.POSITIVE_INFINITY;

  for (const candidate of candidates) {
    const distance = editDistance(needle, candidate.toLowerCase());
    if (distance < smallest) {
      nearest = candidate;
      smallest = distance;
    }
  }

  return smallest <= threshold ? nearest : undefined;
}
