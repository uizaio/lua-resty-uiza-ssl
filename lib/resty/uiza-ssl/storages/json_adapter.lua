-- local cjson = require "cjson.safe"
local json = require "json"

local _M = {}

function _M.new()
  return setmetatable({}, { __index = _M })
end

function _M.encode(_, data)
  return json.encode(data)
end

function _M.decode(_, string)
  return json.decode(string)
end

return _M
