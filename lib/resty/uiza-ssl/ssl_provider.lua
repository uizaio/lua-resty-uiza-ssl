local ltn12 = require "ltn12"
local https = require "ssl.https"
local json = require "json"
local jwt = require "resty.jwt"
local parse_time = require "resty.uiza-ssl.utils.parse_time"
local base64_decode = require "resty.uiza-ssl.utils.base64_decode"

local _M = {}

https.TIMEOUT = 5

local function request_certificate(crt_uri, jwt_token)
    local response = {}
    local rqbody=''
    local res, code, responseHeader, status = https.request{
        url = crt_uri,
        method = "GET",
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = rqbody:len(),
            ["Authorization"] = jwt_token 
        },
        source = ltn12.source.string(rqbody),
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
            expiry = parse_time(resp["not_after"])
        }, nil
    end
    ngx.log(ngx.ERR, 'uiza-ssl: data error')
    return nil, "uiza-ssl: data error"
end

local function request_certificate_data(crt_data_uri, jwt_token) 
    local response = {}
    local rqbody= ''
    local res, code, responseHeader, status = https.request{
        url = crt_data_uri,
        method = "GET",
        headers = { 
            ["Content-Type"] = "application/json",
            ["Content-Length"] = rqbody:len(),
            ["Authorization"] = jwt_token 
        },
        source = ltn12.source.string(rqbody),
        sink = ltn12.sink.table(response)
    }
    if code ~= 200 then
        ngx.log(ngx.ERR, "uiza-ssl: http request certificate failed: ", status)
        return nil, "uiza-ssl: http request certificate failed: " .. status
    end
    local resp = json.decode(table.concat(response))
    if resp and resp["tls_cert"] and resp["tks_key"] then
        local cert_pem, cert_err = base64_decode(resp['tls_cert'])
        local privkey_pem, privkey_err = base64_decode(resp['tks_key'])
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

    local secret_path = domain:gsub(".", "-")
    secret_path = 'wildcard-' .. secret_path .. '-tls'
    ngx.log(ngx.ERR, 'secret_path: ', secret_path)
    local crt_uri = uiza_ssl_instance:get("crt_uri")
    assert(type(crt_uri) == "string", "crt_uri must be a string")
    -- Run 2 request to API, to get certificat info and data
    -- Save data to storage
    local crt_data_uri = uiza_ssl_instance:get("crt_data_uri")
    assert(type(crt_data_uri) == "string", "crt_data_uri must be a string")
    local secret_key = uiza_ssl_instance:get("secret_key")
    assert(type(secret_key) == "string", "secret_key must be a string")

    local jwt_token = jwt:sign(secret_key, { 
        header={typ="JWT",alg="HS256"},
        payload= ''
    })
    -- get certificate info: include secret name and expiry
    local cert_info, cert_info_err = request_certificate(crt_uri .. "/" .. secret_path, jwt_token)
    if cert_info and cert_info["expiry"] and cert_info["secret_name"] then
        -- get certificate dat from secret name
        local cert_data, cert_data_err = request_certificate_data(crt_data_uri .. "/" .. cert_info["secret_name"], jwt_token)
        if cert_data and cert_data["cert_pem"] and cert_data["privkey_pem"] then
            local storage = uiza_ssl_instance.storage
            storage:set_cert(domain, cert_data["privkey_pem"], cert_data["cert_pem"], cert_info["expiry"])
            local cert = {
                ["cert_pem"]=cert_data["cert_pem"],
                ["privkey_pem"]=cert_data["privkey_pem"],
                ["expiry"]=tonumber(cert_info["expiry"])
            }
            return cert, nil
        end
    end
    ngx.log(ngx.ERR, "uiza-ssl: data error")
    return nil, "uiza-ssl: data error"
end

return _M
