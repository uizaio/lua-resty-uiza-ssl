require "resty.uiza-ssl.utils.random_seed"
local shell_blocking = require "shell-games"
local str = require "resty.string"

local function check_dependencies()
  local runtime_dependencies = {
    "bash",
    "curl",
    "diff",
    "grep",
    "mktemp",
    "openssl",
    "sed",
  }
  for _, bin in ipairs(runtime_dependencies) do
    local _, err = shell_blocking.capture_combined({ "command", "-v", bin })
    if(err) then
      ngx.log(ngx.ERR, "uiza-ssl: `" .. bin .. "` was not found in PATH. Please install `" .. bin .. "` first.")
    end
  end
end

local function generate_config(uiza_ssl_instance)
  local base_dir = uiza_ssl_instance:get("dir")
  local _, tmp_mkdir_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/tmp" })
  if tmp_mkdir_err then
    ngx.log(ngx.ERR, "uiza-ssl: failed to create tmp dir: ", tmp_mkdir_err)
  end

  local _, tmp_chmod_err = shell_blocking.capture_combined({ "chmod", "777", base_dir .. "/tmp" })
  if tmp_chmod_err then
    ngx.log(ngx.ERR, "uiza-ssl: failed to create tmp dir permissions: ", tmp_chmod_err)
  end
  
  local _, mkdir_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/letsencrypt" }, { umask = "0022" })
  if mkdir_err then
    ngx.log(ngx.ERR, "uiza-ssl: failed to create letsencrypt/conf.d dir: ", mkdir_err)
  end

  local _, chmod_err = shell_blocking.capture_combined({ "chmod", "777", base_dir .. "/letsencrypt" })
  if chmod_err then
    ngx.log(ngx.ERR, "uiza-ssl: failed to create letsencrypt dir permissions: ", chmod_err)
  end
end

local function setup_storage(uiza_ssl_instance)
  local storage_adapter = require "resty.uiza-ssl.storages.storage_adapter"
  local storage_adapter_instance = storage_adapter.new(uiza_ssl_instance)
  if storage_adapter_instance.setup then
    storage_adapter_instance:setup()
  end

  local json_adapter = require "resty.uiza-ssl.storages.json_adapter"
  local json_adapter_instance = json_adapter.new(uiza_ssl_instance)

  local storage = require "resty.uiza-ssl.storages.storage"
  local storage_instance = storage.new({
    adapter = storage_adapter_instance,
    json_adapter = json_adapter_instance,
  })
  uiza_ssl_instance.storage = storage_instance
end

return function(uiza_ssl_instance)
  check_dependencies()
  generate_config(uiza_ssl_instance)
  setup_storage(uiza_ssl_instance)
end
