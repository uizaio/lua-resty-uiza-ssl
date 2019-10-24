# lua-resty-uiza-ssl
Auto renewal certificate inside OpenResty/nginx with UIZA API.

## Requirements

* OpenResty 1.9.7.2 or higher
* ngx_lua 0.10.0 or higher
* OpenSSL 1.0.2e or higher

## Installation

```bash
sudo luarocks install shell-games
git clone https://github.com/namndbka/lua-resty-uiza-ssl.git
cp -R lua-resty-uiza-ssl/lib/resty <your_lua_lib_path>
```

```bash
# Create /opt/resty-uiza-ssl and make sure it's writable permission
$ sudo mkdir /opt/resty-uiza-ssl
$ sudo chmod +x /opt/resty-uiza-ssl
```
Implement the necessary configuration inside your nginx config. Here is a minimal example:

```lua
events {
  worker_connections 1024;
}

http {
  # The "uiza_ssl" shared dict should be defined with enough storage space to
  # hold your certificate data. 1MB of storage holds certificates for
  # approximately 100 separate domains.
  lua_shared_dict uiza_ssl 1m;
  lua_shared_dict uiza_ssl_settings 64k;
  # Initial setup tasks.
  init_by_lua_block {
    uiza_ssl = (require "resty.uiza-ssl").new()
    -- Defaults to not allowing any domains, so this must be configured.
    uiza_ssl:set("allow_domain", function(domain)
        return ngx.re.match(domain, "(allow_domain)$", "ijo")
    end)
    -- return allow_domain when using for wildcard, type *.allow_domain 
    uiza_ssl:set("request_domain", function(ssl, ssl_options)
        local domain, err = ssl.server_name()
        if (ngx.re.match(domain, "(allow_domain)$", "ijo")) then
            domain = allow_domain
        end
        return domain, err
    end)
	uiza_ssl:set("crt_uri", "<uri_of_certificate>")
	uiza_ssl:set("crt_data_uri", "<uri_of_certificate_data>")
   uiza_ssl:init()
  }

  init_worker_by_lua_block {
    uiza_ssl:init_worker()
  }

  # HTTPS server
  server {
    listen 443 ssl;

    # Dynamic handler for issuing or returning certs for SNI domains.
    ssl_certificate_by_lua_block {
      uiza_ssl:ssl_certificate()
    }

    # You must still define a static ssl_certificate file for nginx to start.
    #
    # You may generate a self-signed fallback with:
    #
    # openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    #   -subj '/CN=sni-support-required-for-valid-ssl' \
    #   -keyout <path_init_key> -out <path_init_cert>
    ssl_certificate <path_init_cert>;
    ssl_certificate_key <path_init_key>;
  }
```

## Configuration

Additional configuration options can be set on the uiza_ssl instance that is created:

### `allow_domain`

Default: `function(domain, uiza_ssl, ssl_options, renewal) return false end`

A function that determines whether the incoming domain should automatically issue a new SSL certificate.

By default, `resty-uiza-ssl` will not perform any SSL registrations until you define the `allow_domain` function. You may return `true` to handle all possible domains.

The callback function's arguments are:

- `domain`: The domain of the incoming request.
- `uiza_ssl`: The current uiza-ssl instance.
- `ssl_options`: A table of optional configuration options that were passed to the [`ssl_certificate` function](#ssl_certificate-configuration). This can be used to customize the behavior on a per nginx `server` basis (see example in [`request_domain`](#request_domain)). Note, this option is ***not*** passed in when this function is called for renewals, so your function should handle that accordingly.
- `renewal`: Boolean value indicating whether this function is being called during certificate renewal or not. When `true`, the `ssl_options` argument will not be present.

*Example*:

```lua
uiza_ssl:set("allow_domain", function(domain, uiza_ssl, ssl_options, renewal)
  return ngx.re.match(domain, "^(example.com|example.net)$", "ijo")
end)
```
### `dir`

Default: `/etc/resty-uiza-ssl`

The base directory used for storing configuration, temporary files, and certificate files (if using the file storage adapter). This directory must be writable by the user nginx workers run as.

*Example:*

```lua
uiza_ssl:set("dir", "/some/other/location")
```

### `renew_check_interval`

Default: `86400`

How frequently (in seconds) all of the domains should be checked for certificate renewals. Defaults to checking every 1 day. Certificates will automatically be renewed if the expire in less than 30 days.

*Example:*

```lua
uiza_ssl:set("renew_check_interval", 172800)
```

### `request_domain`

Default: `function(ssl, ssl_options) return ssl.server_name() end`

A function that determines the hostname of the request. By default, the SNI domain is used, but a custom function can be implemented to determine the domain name for non-SNI requests (by basing the domain on something that can be determined outside of SSL, like the port or IP address that received the request).

The callback function's arguments are:

- `ssl`: An instance of the [`ngx.ssl`](https://github.com/openresty/lua-resty-core/blob/master/lib/ngx/ssl.md) module.
- `ssl_options`: A table of optional configuration options that were passed to the [`ssl_certificate` function](#ssl_certificate-configuration). This can be used to customize the behavior on a per nginx server basis.

*Example:*

This example, along with the accompanying nginx `server` blocks, will default to SNI domain names, but for non-SNI clients will respond with predefined hosts based on the connecting port. Connections to port 9000 will register and return a certificate for `foo.example.com`, while connections to port 9001 will register and return a certificate for `bar.example.com`. Any other ports will return the default nginx fallback certificate.

```lua
uiza_ssl:set("request_domain", function(ssl, ssl_options)
  local domain, err = ssl.server_name()
  if (not domain or err) and ssl_options and ssl_options["port"] then
    if ssl_options["port"] == 9000 then
      domain = "foo.example.com"
    elseif ssl_options["port"] == 9001 then
      domain = "bar.example.com"
    end
  end

  return domain, err
end)
server {
  listen 9000 ssl;
  ssl_certificate_by_lua_block {
    uiza_ssl:ssl_certificate({ port = 9000 })
  }
}

server {
  listen 9001 ssl;
  ssl_certificate_by_lua_block {
    uiza_ssl:ssl_certificate({ port = 9001 })
  }
}
```

### `ssl_certificate` Configuration

The `ssl_certificate` function accepts an optional table of configuration options. These options can be used to customize and control the SSL behavior on a per nginx `server` basis. Some built-in options may control the default behavior of lua-resty-auto-ssl, but any other custom data can be given as options, which will then be passed along to the [`allow_domain`](#allow_domain) and [`request_domain`](#request_domain) callback functions.

Built-in configuration options:

### generate_certs

Default: `true`

This variable can be used to disable generating certs on a per server block location.

*Example:*

```lua
server {
  listen 8443 ssl;
  ssl_certificate_by_lua_block {
    uiza_ssl:ssl_certificate({ generate_certs = false })
  }
}
```
