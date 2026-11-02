import type { RateLimiter } from "../tickets/rateLimit";

/**
 * The hand-off (go/route.ts) starts the Pretix email search on the email the
 * auth cookie CLAIMS while the auth server verifies the cookie, so the slowest
 * lookup no longer waits for that round trip. The claim is unverified, so
 * these two rules keep it a hint: a forged cookie can start a bounded number
 * of searches, never get a token.
 */

/** Early-start budgets, both per serverless instance (see rateLimit.ts). */
export interface EarlyStartLimits {
  /** Keyed by visitor address. Loose: attendees at the venue share a few NAT addresses. */
  perIp: RateLimiter;
  /** One key for everyone: the cap on searches unverified requests can start. */
  global: RateLimiter;
}

/**
 * Whether this request may start the search before verification. Only with
 * the address Netlify itself sets (`x-nf-client-connection-ip`, never a
 * client-supplied header) and within both budgets; otherwise the search
 * simply starts after verification, as it always did. Nobody is refused.
 */
export function canStartEarly(clientIp: string | null, limits: EarlyStartLimits): boolean {
  if (!clientIp) return false;
  return limits.perIp.allow(clientIp) && limits.global.allow("all");
}

/**
 * What to do with a search started on `claimedEmail` once the auth server has
 * answered with `verifiedEmail` (null: not signed in). "reuse" only for the
 * very same email; "restart" when it differs, e.g. a token issued before the
 * account changed its email, which still gets today's lookup on the verified
 * email rather than a sign-in page.
 */
export function resolveIdentity(
  claimedEmail: string,
  verifiedEmail: string | null | undefined
): "unauthenticated" | "reuse" | "restart" {
  if (!verifiedEmail) return "unauthenticated";
  return verifiedEmail === claimedEmail ? "reuse" : "restart";
}
