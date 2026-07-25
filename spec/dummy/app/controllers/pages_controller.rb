require "cru_iap"

# The consumer side of the gem's contract, wired the way the README's reference
# wiring says to wire it — resolve the identity ONCE per request, and fail
# closed. Kept intentionally close to that snippet: if the README drifts from
# what actually works, these specs should be what catches it.
class PagesController < ActionController::API
  GATED_CONTENT = "the-gated-content".freeze

  before_action :require_iap!, only: %i[gated repeated admin]

  def public_page
    render plain: "public ok"
  end

  def gated
    render json: {
      content: GATED_CONTENT,
      email: iap_identity.email,
      name: iap_identity.name,
      reason: iap_identity.reason
    }
  end

  # Reads the identity four times, through both the memoized reader and the
  # before_action that already ran. A caller doing this must not re-verify the
  # JWT (expensive, and it re-logs every rejection once per call site).
  def repeated
    emails = 4.times.map { iap_identity.email }
    render json: { emails: emails, object_ids: emails.map(&:object_id).uniq.size }
  end

  # What the app believes about its own host, plus whether the forged header
  # survived into the Rack env at all.
  def host
    render json: {
      host: request.host,
      host_with_port: request.host_with_port,
      forwarded_host_header: request.get_header("HTTP_X_FORWARDED_HOST"),
      original_url: request.original_url
    }
  end

  def admin
    render plain: "admin ok"
  end

  private

  # Memoized per request. `defined?` rather than `||=` so a rejection (which
  # is a falsey-ish outcome, not nil) is cached too — re-verifying on the
  # failure path is the mistake this guards against.
  def iap_identity
    return @iap_identity if defined?(@iap_identity)

    @iap_identity = CruIap::TokenVerifier.from_request(request)
  end

  def require_iap!
    return if iap_identity.ok?

    # Fail closed: no content, and the reason is echoed only because this is a
    # test app and the specs assert on it.
    render json: { error: "unauthenticated", reason: iap_identity.reason }, status: :unauthorized
  end
end
