/**
 * The header IAP injects. Exposed because infra config and test fixtures
 * legitimately need the wire name — application code should not, and should
 * call `verifyRequest` instead of reaching for it.
 */
export const HEADER = "x-goog-iap-jwt-assertion";

/**
 * Anything we can pull the assertion off. Deliberately structural rather than
 * a union of framework types, so this package imports neither `next` nor
 * `node:http` and stays usable from the Edge runtime.
 *
 *  - Web `Request` / `NextRequest` / `Headers`   → `.headers.get(name)` / `.get(name)`
 *  - Node `IncomingMessage`                      → `.headers[name]`
 *  - `Object.fromEntries(headers)` and friends   → plain record
 */
export type HeaderSource =
  | { headers: HeaderCarrier }
  | HeaderCarrier;

type HeaderCarrier =
  | { get(name: string): string | null | undefined }
  | Record<string, string | string[] | undefined>;

/**
 * Pull the raw assertion JWT off a request, or undefined if absent.
 *
 * Header lookup is case-insensitive: `Headers.get` already is, and for plain
 * records we scan case-insensitively rather than trusting the caller to have
 * lowercased (Node lowercases; `Object.fromEntries` of a Headers object does
 * too, but a hand-built literal may not).
 */
export function assertionFrom(source: HeaderSource): string | undefined {
  return headerFrom(source, HEADER);
}

/**
 * Read one named header off any `HeaderSource`. Internal to the package —
 * identity-headers.ts needs the identical case-insensitive, duplicate-refusing
 * lookup, and a second copy of it there would drift.
 *
 * A repeated header arrives as an array in Node. Neither IAP nor our own gate
 * produces that shape, so treat it as absent rather than guessing which to
 * trust — the caller then fails closed.
 */
export function headerFrom(source: HeaderSource, name: string): string | undefined {
  const carrier = hasHeaders(source) ? source.headers : source;
  const raw = readHeader(carrier, name);
  if (Array.isArray(raw)) return raw.length === 1 ? raw[0] : undefined;
  return raw ?? undefined;
}

function hasHeaders(source: HeaderSource): source is { headers: HeaderCarrier } {
  return (
    typeof source === "object" &&
    source !== null &&
    "headers" in source &&
    typeof (source as { headers?: unknown }).headers === "object" &&
    (source as { headers?: unknown }).headers !== null
  );
}

function readHeader(
  carrier: HeaderCarrier,
  name: string,
): string | string[] | null | undefined {
  if (typeof (carrier as { get?: unknown }).get === "function") {
    return (carrier as { get(n: string): string | null | undefined }).get(name);
  }
  const record = carrier as Record<string, string | string[] | undefined>;
  if (name in record) return record[name];
  const hit = Object.keys(record).find((key) => key.toLowerCase() === name);
  return hit === undefined ? undefined : record[hit];
}
