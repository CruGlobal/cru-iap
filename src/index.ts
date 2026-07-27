export { REASONS, isKnownReason } from "./reasons.js";
export type { Reason, ResultReason } from "./reasons.js";

export { HEADER, assertionFrom } from "./request.js";
export type { HeaderSource } from "./request.js";

export {
  IAP_ISSUER,
  IAP_JWKS_URL,
  resetJwksCache,
  verify,
  verifyRequest,
} from "./verifier.js";
export type { Logger, VerifyOptions, VerifyResult } from "./verifier.js";

export { LOGIN_QUERY, LOGOUT_QUERY, loginUrl, logoutUrl } from "./urls.js";

export {
  CLOUD_MARKERS,
  DEV_BYPASS_EMAIL_VAR,
  DEV_BYPASS_NAME_VAR,
  devBypass,
} from "./dev-bypass.js";
export type { DevBypassOptions, DevBypassResult } from "./dev-bypass.js";
