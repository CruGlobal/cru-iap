RSpec.describe Cru::Iap::StripForwardedHost do
  let(:downstream) { ->(env) { [200, {}, [env.key?("HTTP_X_FORWARDED_HOST").to_s]] } }
  let(:middleware) { described_class.new(downstream) }

  it "removes a forged X-Forwarded-Host before the app sees it" do
    env = { "HTTP_HOST" => "go.cru.org", "HTTP_X_FORWARDED_HOST" => "beacon.cru.org" }
    _status, _headers, body = middleware.call(env)
    expect(body).to eq(["false"])
    expect(env).not_to have_key("HTTP_X_FORWARDED_HOST")
  end

  it "leaves the real Host header alone" do
    env = { "HTTP_HOST" => "go.cru.org", "HTTP_X_FORWARDED_HOST" => "beacon.cru.org" }
    middleware.call(env)
    expect(env["HTTP_HOST"]).to eq("go.cru.org")
  end

  it "passes through when the header is absent" do
    env = { "HTTP_HOST" => "go.cru.org" }
    status, _headers, body = middleware.call(env)
    expect(status).to eq(200)
    expect(body).to eq(["false"])
  end

  it "returns the downstream response unchanged" do
    app = ->(_env) { [204, { "content-type" => "text/plain" }, ["hi"]] }
    expect(described_class.new(app).call({})).to eq([204, { "content-type" => "text/plain" }, ["hi"]])
  end
end
