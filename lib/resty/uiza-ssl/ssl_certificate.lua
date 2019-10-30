local lock = require "resty.lock"
local ssl = require "ngx.ssl"
local ssl_provider = require "resty.uiza-ssl.ssl_provider"

local function convert_to_der_and_cache(domain, cert)
  -- Convert certificate from PEM to DER format.
  local cert_der, cert_der_err = ssl.cert_pem_to_der(cert["cert_pem"])
  if not cert_der or cert_der_err then
    return nil, "uiza-ssl: failed to convert certificate chain from PEM to DER: " .. (cert_der_err or "")
  end

  -- Convert private key from PEM to DER format.
  local privkey_der, privkey_der_err = ssl.priv_key_pem_to_der(cert["privkey_pem"])
  if not privkey_der or privkey_der_err then
    return nil, "uiza-ssl: failed to convert private key from PEM to DER: " .. (privkey_der_err or "")
  end

  -- Cache DER formats in memory for 1 hour (so renewals will get picked up
  -- across multiple servers).
  local _, set_cert_err, set_cert_forcible = ngx.shared.uiza_ssl:set("domain:cert_der:" .. domain, cert_der, 3600)
  if set_cert_err then
    ngx.log(ngx.ERR, "uiza-ssl: failed to set shdict cache of certificate chain for " .. domain .. ": ", set_cert_err)
  elseif set_cert_forcible then
    ngx.log(ngx.ERR, "uiza-ssl: 'lua_shared_dict uiza_ssl' might be too small - consider increasing its configured size (old entries were removed while adding certificate chain for " .. domain .. ")")
  end

  local _, set_privkey_err, set_privkey_forcible = ngx.shared.uiza_ssl:set("domain:privkey_der:" .. domain, privkey_der, 3600)
  if set_privkey_err then
    ngx.log(ngx.ERR, "uiza-ssl: failed to set shdict cache of private key for " .. domain .. ": ", set_privkey_err)
  elseif set_privkey_forcible then
    ngx.log(ngx.ERR, "uiza-ssl: 'lua_shared_dict uiza_ssl' might be too small - consider increasing its configured size (old entries were removed while adding private key for " .. domain .. ")")
  end

  return {
    cert_der = cert_der,
    privkey_der = privkey_der,
  }
end

local function issue_cert_unlock(domain, storage, local_lock, distributed_lock_value)
  if local_lock then
    local _, local_unlock_err = local_lock:unlock()
    if local_unlock_err then
      ngx.log(ngx.ERR, "uiza-ssl: failed to unlock: ", local_unlock_err)
    end
  end

  if distributed_lock_value then
    local _, distributed_unlock_err = storage:issue_cert_unlock(domain, distributed_lock_value)
    if distributed_unlock_err then
      ngx.log(ngx.ERR, "uiza-ssl: failed to unlock: ", distributed_unlock_err)
    end
  end
end

local function issue_cert(uiza_ssl_instance, storage, domain)
  -- Before issuing a cert, create a local lock to ensure multiple workers
  -- don't simultaneously try to register the same cert.
  local local_lock, new_local_lock_err = lock:new("uiza_ssl", { exptime = 30, timeout = 30 })
  if new_local_lock_err then
    ngx.log(ngx.ERR, "uiza-ssl: failed to create lock: ", new_local_lock_err)
    return
  end
  local _, local_lock_err = local_lock:lock("issue_cert:" .. domain)
  if local_lock_err then
    ngx.log(ngx.ERR, "uiza-ssl: failed to obtain lock: ", local_lock_err)
    return
  end

  -- Also add a lock to the configured storage adapter, which allows for a
  -- distributed lock across multiple servers (depending on the storage
  -- adapter).
  local distributed_lock_value, distributed_lock_err = storage:issue_cert_lock(domain)
  if distributed_lock_err then
    ngx.log(ngx.ERR, "uiza-ssl: failed to obtain lock: ", distributed_lock_err)
    issue_cert_unlock(domain, storage, local_lock, nil)
    return
  end

  -- After obtaining the local and distributed lock, see if the certificate
  -- has already been registered.
  local cert, err = storage:get_cert(domain)
  if err then
    ngx.log(ngx.ERR, "uiza-ssl: error fetching certificate from storage for ", domain, ": ", err)
  end

  if cert and cert["cert_pem"] and cert["privkey_pem"] then
    issue_cert_unlock(domain, storage, local_lock, distributed_lock_value)
    return cert
  end

  ngx.log(ngx.NOTICE, "uiza-ssl: issuing new certificate for ", domain)
  cert, err = ssl_provider.issue_cert(uiza_ssl_instance, domain)
  if err then
    ngx.log(ngx.ERR, "uiza-ssl: issuing new certificate failed: ", err)
  end

  issue_cert_unlock(domain, storage, local_lock, distributed_lock_value)
  return cert, err
end

local function get_cert_der(uiza_ssl_instance, domain, ssl_options)
  -- Look for the certificate in shared memory first.
  local cert_der = ngx.shared.uiza_ssl:get("domain:cert_der:" .. domain)
  local privkey_der = ngx.shared.uiza_ssl:get("domain:privkey_der:" .. domain)
  if cert_der and privkey_der then
    return {
      cert_der = cert_der,
      privkey_der = privkey_der,
      newly_issued = false,
    }
  end

  -- Check to ensure the domain is one we allow for handling SSL.
  --
  -- Note: We perform this after the memory lookup, so more costly
  -- "allow_domain" lookups can be avoided for cached certs. However, we will
  -- perform this before the storage lookup, since the storage lookup could
  -- also be more costly (or blocking in the case of the file storage adapter).
  -- We may want to consider caching the results of allow_domain lookups
  -- (including negative caching or disallowed domains).
  local allow_domain = uiza_ssl_instance:get("allow_domain")
  if not allow_domain(domain, uiza_ssl_instance, ssl_options, false) then
    return nil, "domain not allowed"
  end

  -- Next, look for the certificate in permanent storage (which can be shared
  -- across servers depending on the storage).
  local storage = uiza_ssl_instance.storage
  local cert, get_cert_err = storage:get_cert(domain)
  if get_cert_err then
    ngx.log(ngx.ERR, "uiza-ssl: error fetching certificate from storage for ", domain, ": ", get_cert_err)
  end

  if cert and cert["cert_pem"] and cert["privkey_pem"] then
    local cert_der = convert_to_der_and_cache(domain, cert)
    cert_der["newly_issued"] = false
    return cert_der
  end

  -- Finally, issue a new certificate if one hasn't been found yet.
  if not ssl_options or ssl_options["generate_certs"] ~= false then
    cert = issue_cert(uiza_ssl_instance, storage, domain)
    if cert and cert["cert_pem"] and cert["privkey_pem"] then
      local cert_der = convert_to_der_and_cache(domain, cert)
      cert_der["newly_issued"] = true
      return cert_der
    end
  else
    return nil, "did not issue certificate, because the generate_certs setting is false"
  end

  -- Return an error if issuing the certificate failed.
  return nil, "failed to get or issue certificate"
end

local function set_response_cert(uiza_ssl_instance, domain, cert_der)
  local ok, err

  -- Clear the default fallback certificates (defined in the hard-coded nginx
  -- config).
  ok, err = ssl.clear_certs()
  if not ok then
    return nil, "failed to clear existing (fallback) certificates - " .. (err or "")
  end

  -- Set the public certificate chain.
  ok, err = ssl.set_der_cert(cert_der["cert_der"])
  if not ok then
    return nil, "failed to set certificate - " .. (err or "")
  end

  -- Set the private key.
  ok, err = ssl.set_der_priv_key(cert_der["privkey_der"])
  if not ok then
    return nil, "failed to set private key - " .. (err or "")
  end
end

local function do_ssl(uiza_ssl_instance, ssl_options)
  -- Determine the domain making the SSL request with SNI.
  local request_domain = uiza_ssl_instance:get("request_domain")
  local domain, domain_err = request_domain(ssl, ssl_options)
  if not domain or domain_err then
    ngx.log(ngx.WARN, "uiza-ssl: could not determine domain for request (SNI not supported?) - using fallback - " .. (domain_err or ""))
    return
  end

  -- Get or issue the certificate for this domain.
  local cert_der, get_cert_der_err = get_cert_der(uiza_ssl_instance, domain, ssl_options)
  if get_cert_der_err then
    if get_cert_der_err == "domain not allowed" then
      ngx.log(ngx.NOTICE, "uiza-ssl: domain not allowed - using fallback - ", domain)
    else
      ngx.log(ngx.ERR, "uiza-ssl: could not get certificate for ", domain, " - using fallback - ", get_cert_der_err)
    end
    return
  elseif not cert_der or not cert_der["cert_der"] or not cert_der["privkey_der"] then
    ngx.log(ngx.ERR, "uiza-ssl: certificate data unexpectedly missing for ", domain, " - using fallback")
    return
  end

  -- Set the certificate on the response.
  local _, set_response_cert_err = set_response_cert(uiza_ssl_instance, domain, cert_der)
  if set_response_cert_err then
    ngx.log(ngx.ERR, "uiza-ssl: failed to set certificate for ", domain, " - using fallback - ", set_response_cert_err)
    return
  end
end

return function(uiza_ssl_instance, ssl_options)
  local ok, err = pcall(do_ssl, uiza_ssl_instance, ssl_options)
  if not ok then
    ngx.log(ngx.ERR, "uiza-ssl: failed to run do_ssl: ", err)
  end
end
