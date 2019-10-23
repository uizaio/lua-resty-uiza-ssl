local ltn12 = require "ltn12"
local https = require "ssl.https"
local http = require "socket.http"
local json = require "json"
local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' -- You will need this for encoding/decoding
local _M = {}

http.TIMEOUT = 5
https.TIMEOUT = 5
-- decoding base64
local function decode(data)
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
            return string.char(c)
    end))
end
-- convert string (format: '2019-11-25T14:07:39Z') to os.time
local function makeTimeStamp(s)
	if s then
		local year, month, day, hour, min, sec, tzd;
		year, month, day, hour, min, sec, tzd = s:match("^(%d%d%d%d)-?(%d%d)-?(%d%d)T(%d%d):(%d%d):(%d%d)%.?%d*([Z+%-].*)$");
		if year then
			local time_offset = os.difftime(os.time(os.date("*t")), os.time(os.date("!*t"))); -- to deal with local timezone
			local tzd_offset = 0;
			if tzd ~= "" and tzd ~= "Z" then
				local sign, h, m = tzd:match("([+%-])(%d%d):?(%d*)");
				if not sign then return; end
				if #m ~= 2 then m = "0"; end
				h, m = tonumber(h), tonumber(m);
				tzd_offset = h * 60 * 60 + m * 60;
				if sign == "-" then tzd_offset = -tzd_offset; end
			end
			sec = (sec + time_offset) - tzd_offset;
			return os.time({year=year, month=month, day=day, hour=hour, min=min, sec=sec, isdst=false});
		end
	end
end

local function request_certificate(crt_uri)
    local response = {}
    local httpc = http
    if(tostring(crt_uri):startswith('https://')) then 
        httpc = https
    end
    local res, code, responseHeader, status = httpc.request{
        url = crt_uri,
        method = "GET",
        headers = {
            ["Content-Type"] = "application/json",
        },
        source = ltn12.source.string(''),
        sink = ltn12.sink.table(response)
    }
    if code ~= 200 then
        ngx.log(ngx.ERR, "uiza-ssl: http check_expiry_time failed: ", status)
        return nil, "http failure"
    end
    local resp = json.decode(table.concat(response))
    if resp and resp["secret_name"] and resp["not_after"] then
        return {
            secret_name = resp["secret_name"],
            expiry = makeTimeStamp(resp["not_after"])
        }, nil
    end
    ngx.log(ngx.ERR, 'uiza-ssl: data error')
    return nil, "uiza-ssl: data error"
end

local function request_certificate_data(crt_data_uri) 
    local response = {}
    local httpc = http
    if(tostring(crt_data_uri):startswith('https://')) then 
        httpc = https
    end
    local res, code, responseHeader, status = httpc.request{
        url = crt_data_uri,
        method = "GET",
        headers = { ["Content-Type"] = "application/json" },
        source = ltn12.source.string(''),
        sink = ltn12.sink.table(response)
    }
    if code ~= 200 then
        ngx.log(ngx.ERR, "uiza-ssl: http request certificate failed: ", status)
        return nil, "uiza-ssl: http request certificate failed: " .. status
    end
    local resp = json.decode(table.concat(response))
    if resp and resp["tls_cert"] and resp["tks_key"] then
        local cert_pem, err1 = decode(resp['tls_cert'])
        local privkey_pem, err2 = decode(resp['tks_key'])
        local cert = {
            ["cert_pem"]=cert_pem,
            ["privkey_pem"]=privkey_pem
        }
        return cert, nil
    end
    ngx.log(ngx.ERR, "uiza-ssl: data error")
    return nil, "uiza-ssl: data error"
end

function _M.issue_cert(uiza_ssl_instance, domain)
    assert(type(domain) == "string", "domain must be a string")
    local crt_uri = uiza_ssl_instance:get("crt_uri")
    assert(type(crt_uri) == "string", "crt_uri must be a string")
    -- Run 2 request to API, to get certificat info and data
    -- Save data to storage
    local crt_data_uri = uiza_ssl_instance:get("crt_data_uri")
    assert(type(crt_data_uri) == "string", "crt_data_uri must be a string")
    -- get certificate info: include secret name and expiry
    local cert_info, cert_info_err = request_certificate(crt_uri)
    if cert_info and cert_info["expiry"] and cert_info["secret_name"] then
        -- get certificate dat from secret name
        local cert_data, cert_data_err = request_certificate_data(crt_data_uri)
        if cert_data and cert_data["cert_pem"] and cert_data["privkey_pem"] then
            local storage = uiza_ssl_instance.storage
            storage:set_cert(domain, cert_data["privkey_pem"], cert_data["cert_pem"], cert_info["expiry"])
            cert_data.insert(expiry, tonumber(cert_info["expiry"]))
            return cert_data, nil
        end
    end
    ngx.log(ngx.ERR, "uiza-ssl: data error")
    return nil, "uiza-ssl: data error"
end

return _M
