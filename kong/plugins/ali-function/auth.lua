local openssl_mac = require "resty.openssl.mac"
local b64 = require "ngx.base64"

local openssl_sign = {
  hmac_sha256 = function(data, key) return openssl_mac.new(key, "HMAC", nil, "sha256"):final(data) end
}

local function build_canonicalized_headers(hdrs)
    local keys = {}
    for k in pairs(hdrs) do
        local kl = k:lower()
        if kl:match("^x%-acs%-") then
            table.insert(keys, kl)
        end
    end
    table.sort(keys)

    local canon = ""
    for _, kl in ipairs(keys) do
        -- find ori key
        local orig_k = nil
        for k in pairs(hdrs) do
            if k:lower() == kl then
                orig_k = k
                break
            end
        end
        canon = canon .. orig_k:lower() .. ":" .. tostring(hdrs[orig_k]):gsub("^%s+", ""):gsub("%s+$", "") .. "\n"
    end
    return canon
end

local function sign_request(str, key)
    local digest = openssl_sign.hmac_sha256(str, key)
    return b64.encode_base64url(digest)
end


local function get_gmt_date()
    return os.date("!%a, %d %b %Y %H:%M:%S GMT")
end

local function build_signature(access_key_secret, host, uri, method)
    -- Gen x-acs-* header
    local date = get_gmt_date()
    local headers = {
        ["x-acs-date"] = date,
        ["x-acs-signature-method"] = "ACS3-HMAC-SHA256",
        ["x-acs-signature-nonce"] = tostring(os.time() * 1000 + math.random(0, 999)),
        ["x-acs-version"] = "2016-08-15",
        ["x-acs-signature-version"] = "3.0",
        ["Host"] = host,
        ["Accept"] = "application/json"
    }
    
    local canon_headers_str = build_canonicalized_headers(headers)
    local canonicalized_resource = uri 
    local content_md5 = ""
    local content_type = ""
    local string_to_sign = table.concat({
        method,
        content_md5,
        content_type,
        date,
        canon_headers_str,
        canonicalized_resource
    }, "\n")
 
    local signature = sign_request(string_to_sign, access_key_secret)

    return signature
end

return {
  build_signature = build_signature,
}
