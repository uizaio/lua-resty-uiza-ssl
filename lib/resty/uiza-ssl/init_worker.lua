local random_seed = require "resty.uiza-ssl.utils.random_seed"
local renewal = require "resty.uiza-ssl.renewal"
local shell_blocking = require "shell-games"

return function(uiza_ssl_instance)
  local base_dir = uiza_ssl_instance:get("dir")
  local _, mkdir_locks_err = shell_blocking.capture_combined({ "mkdir", "-p", base_dir .. "/letsencrypt/locks" }, { umask = "0022" })
  if mkdir_locks_err then
    ngx.log(ngx.ERR, "uiza-ssl: failed to create letsencrypt/locks dir: ", mkdir_locks_err)
  end

  -- random_seed was called during the "init" master phase, but we want to
  -- ensure each worker process's random seed is different, so force another
  -- call in the init_worker phase.
  random_seed()

  local storage = uiza_ssl_instance.storage
  local storage_adapter = storage.adapter
  if storage_adapter.setup_worker then
    storage_adapter:setup_worker()
  end

  renewal.spawn(uiza_ssl_instance)
end
