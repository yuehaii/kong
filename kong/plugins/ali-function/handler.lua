local constants     = require "kong.constants"
local http          = require "resty.http"
local kong_meta     = require "kong.meta"
local kong          = kong
local fmt           = string.format
local var           = ngx.var
local auth_util = require "kong.plugins.ali-function.auth"
local build_signature = auth_util.build_signature

local server_tokens = kong_meta._SERVER_TOKENS
local VIA_HEADER    = constants.HEADERS.VIA

local ali = {
  PRIORITY = 748,
  VERSION = kong_meta.version,
}

function ali:access(conf)
  local path do
    if conf.functionversion == "3.0" then
      path = conf.apiversion .. "/functions/" .. conf.functionversion .. "/invocations"
    else
      path = conf.apiversion .. "/services/" .. conf.servicename .. "/functions/" .. conf.functionversion .. "/invocations"
    end
  end

  local host = conf.tenantid .. "." .. conf.hostlocation .. ".fc.aliyuncs.com" 
  local scheme = conf.https and "https" or "http"
  local port = conf.https and 443 or 80
  local uri = fmt("%s://%s:%d", scheme, host, port)

  local request_headers = kong.request.get_headers()
  request_headers["host"] = nil 
  request_headers["Authorization"] = string.format(
    "ACS3-HMAC-SHA256 AccessKeyId=%s, Signature=%s",
    conf.accesskeyid,
    build_signature(conf.accesskeysecret, host, uri, kong.request.get_method())
  )

  local client = http.new()
  client:set_timeout(conf.timeout)
  local res, err = client:request_uri(uri, {
    method = kong.request.get_method(),
    path = path,
    body = kong.request.get_raw_body(),
    query = kong.request.get_query(),
    headers = request_headers,
    ssl_verify = conf.https_verify,
    keepalive_timeout = conf.keepalive,
  })

  if not res then
    kong.log.err(err)
    return kong.response.exit(500, { message = "unexpected error" })
  end

  local response_headers = res.headers
  if var.http2 then
    response_headers["Connection"] = nil
    response_headers["Keep-Alive"] = nil
    response_headers["Proxy-Connection"] = nil
    response_headers["Upgrade"] = nil
    response_headers["Transfer-Encoding"] = nil
  end

  if kong.configuration.enabled_headers[VIA_HEADER] then
    local outbound_via = (var.http2 and "2 " or "1.1 ") .. server_tokens
    response_headers[VIA_HEADER] = response_headers[VIA_HEADER] and response_headers[VIA_HEADER] .. ", " .. outbound_via
                                   or outbound_via
  end

  return kong.response.exit(res.status, res.body, response_headers)
end

return ali
