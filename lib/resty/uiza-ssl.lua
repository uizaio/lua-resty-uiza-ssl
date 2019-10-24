local _M = {}

function _M.new(options)
  if not options then
    options = {}
  end

  if not options["dir"] then
    options["dir"] = "/etc/resty-uiza-ssl"
  end

  if not options["request_domain"] then
    options["request_domain"] = function(ssl, ssl_options) -- luacheck: ignore
      return ssl.server_name()
    end
  end

  if not options["allow_domain"] then
    options["allow_domain"] = function(domain, uiza_ssl, ssl_options, renewal) -- luacheck: ignore
      return false
    end
  end

  if not options["renew_check_interval"] then
    options["renew_check_interval"] = 86400 -- 1 day
  end

  return setmetatable({ options = options }, { __index = _M })
end

function _M.set(self, key, value)
  if key == "storage" then
    ngx.log(ngx.ERR, "uiza-ssl: DEPRECATED: Don't use uiza_ssl:set() for the 'storage' instance. Set directly with uiza_ssl.storage.")
    self.storage = value
    return
  end

  self.options[key] = value
end

function _M.get(self, key)
  if key == "storage" then
    ngx.log(ngx.ERR, "uiza-ssl: DEPRECATED: Don't use uiza_ssl:get() for the 'storage' instance. Get directly with uiza_ssl.storage.")
    return self.storage
  end

  return self.options[key]
end

function _M.init(self)
  local init_master = require "resty.uiza-ssl.init_master"
  init_master(self)
end

function _M.init_worker(self)
  local init_worker = require "resty.uiza-ssl.init_worker"
  init_worker(self)
end

function _M.ssl_certificate(self, ssl_options)
  local ssl_certificate = require "resty.uiza-ssl.ssl_certificate"
  ssl_certificate(self, ssl_options)
end

return _M
