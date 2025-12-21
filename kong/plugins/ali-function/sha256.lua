local function band(a, b) return a % 256 & b % 256 end
local function rshift(a, b) return math.floor(a / 2^b) end
local function lshift(a, b) return (a * 2^b) % 256 end

local function sha256(msg)
    local K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    }

    local function add(a, b)
        return (a + b) & 0xffffffff
    end

    local function bsig0(x)
        return ((x >> 7) | (x << 25)) ~ ((x >> 18) | (x << 14)) ~ (x >> 3)
    end

    local function bsig1(x)
        return ((x >> 17) | (x << 15)) ~ ((x >> 19) | (x << 13)) ~ (x >> 10)
    end

    local function ch(x, y, z)
        return (x & y) ~ (~x & z)
    end

    local function maj(x, y, z)
        return (x & y) ~ (x & z) ~ (y & z)
    end

    local function sig0(x)
        return ((x >> 2) | (x << 30)) ~ ((x >> 13) | (x << 19)) ~ ((x >> 22) | (x << 10))
    end

    local function sig1(x)
        return ((x >> 6) | (x << 26)) ~ ((x >> 11) | (x << 21)) ~ ((x >> 25) | (x << 7))
    end

    local H = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    }

    local msg_len = #msg
    local bytes = { msg:byte(1, msg_len) }

    table.insert(bytes, 0x80)

    while (#bytes + 8) % 64 ~= 0 do
        table.insert(bytes, 0)
    end

    local bit_len = msg_len * 8
    for i = 8, 1, -1 do
        table.insert(bytes, (bit_len >> ((8 - i) * 8)) & 0xff)
    end

    for pos = 1, #bytes, 64 do
        local W = {}
        for j = 1, 16 do
            local idx = pos + (j - 1) * 4
            W[j] = (bytes[idx] << 24) +
                   (bytes[idx + 1] << 16) +
                   (bytes[idx + 2] << 8) +
                   (bytes[idx + 3])
        end

        for j = 17, 64 do
            W[j] = add(add(bsig1(W[j-2]), W[j-7]),
                       add(bsig0(W[j-15]), W[j-16]))
        end

        local a, b, c, d, e, f, g, h =
            H[1], H[2], H[3], H[4],
            H[5], H[6], H[7], H[8]

        for j = 1, 64 do
            local T1 = add(add(add(add(h, sig1(e)), ch(e, f, g)), K[j]), W[j])
            local T2 = add(sig0(a), maj(a, b, c))

            h = g
            g = f
            f = e
            e = add(d, T1)
            d = c
            c = b
            b = a
            a = add(T1, T2)
        end

        H[1] = add(H[1], a)
        H[2] = add(H[2], b)
        H[3] = add(H[3], c)
        H[4] = add(H[4], d)
        H[5] = add(H[5], e)
        H[6] = add(H[6], f)
        H[7] = add(H[7], g)
        H[8] = add(H[8], h)
    end

    local function tohex(n)
        return string.format("%08x", n)
    end

    local result = ""
    for i = 1, 8 do
        result = result .. tohex(H[i])
    end

    return result
end

local function hmac_sha256(key, data)
    if #key > 64 then key = sha256(key, true) end
    key = key .. ("\0"):rep(64 - #key)

    local k_ipad = ""
    local k_opad = ""
    for i = 1, 64 do
        local b = key:sub(i, i):byte()
        k_ipad = k_ipad .. string.char(b ~ 0x36)
        k_opad = k_opad .. string.char(b ~ 0x5c)
    end

    return sha256(k_opad .. sha256(k_ipad .. data))
end

local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

local function b64(data)
    local result = {}
    local line_len = 0
    local line_limit = 76

    for i = 1, #data, 3 do
        local a, b, c = data:byte(i, i + 2)

        local v = a
        table.insert(result, b64chars:sub(rshift(v, 2) + 1, rshift(v, 2) + 1))

        if not b then
            table.insert(result, b64chars:sub(band(lshift(a, 4), 0x3F) + 1, band(lshift(a, 4), 0x3F) + 1))
            table.insert(result, '==')
            break
        else
            v = lshift(band(a, 3), 6) + b
            table.insert(result, b64chars:sub(rshift(v, 4) + 1, rshift(v, 4) + 1))

            if not c then
                table.insert(result, b64chars:sub(band(lshift(b, 2), 0x3F) + 1, band(lshift(b, 2), 0x3F) + 1))
                table.insert(result, '=')
                break
            else
                v = lshift(band(b, 0xF), 2) + rshift(c, 6)
                table.insert(result, b64chars:sub(v + 1, v + 1))

                table.insert(result, b64chars:sub(band(c, 0x3F) + 1, band(c, 0x3F) + 1))
            end
        end

        line_len = line_len + 4
        if line_len >= line_limit then
            table.insert(result, '\r\n')
            line_len = 0
        end
    end

    if line_len > 0 then
        table.insert(result, '\r\n')
    end

    return table.concat(result)
end

return {
    b64 = b64,
    sha256 = sha256,
    hmac_sha256 = hmac_sha256
}