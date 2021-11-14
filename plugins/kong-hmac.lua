--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local ngx        = ngx
local type       = type
local abs        = math.abs
local ngx_time   = ngx.time
local ngx_re     = require("ngx.re")
local ngx_req    = ngx.req
local pairs      = pairs
local ipairs     = ipairs
local hmac_sha1  = ngx.hmac_sha1
local escape_uri = ngx.escape_uri
local core       = require("apisix.core")
local hmac       = require("resty.hmac")
local resty_sha256 = require("resty.sha256")
local restystr = require("resty.string")
local consumer   = require("apisix.consumer")
local ngx_decode_base64 = ngx.decode_base64
local ngx_encode_base64 = ngx.encode_base64

local DIGEST_KEY = "DIGEST"
local SIGNATURE_KEY = "SIGNATURE"
local ALGORITHM_KEY = "ALGORITHM"
local DATE_KEY = "DATE"
local ACCESS_KEY    = "ACCESS-KEY"
local SIGNED_HEADERS_KEY = "SIGNED-HEADERS"
local plugin_name   = "kong-hmac"

local lrucache = core.lrucache.new({
    type = "plugin",
})

local schema = {
    type = "object",
    title = "work with route or service object",
    properties = {},
    additionalProperties = false,
}

local consumer_schema = {
    type = "object",
    title = "work with consumer object",
    properties = {
        access_key = {type = "string", minLength = 1, maxLength = 256},
        secret_key = {type = "string", minLength = 1, maxLength = 256},
        algorithm = {
            type = "string",
            enum = {"hmac-sha1", "hmac-sha256", "hmac-sha512"},
            default = "hmac-sha256"
        },
        clock_skew = {
            type = "integer",
            default = 0
        },
        signed_headers = {
            type = "array",
            items = {
                type = "string",
                minLength = 1,
                maxLength = 50,
            }
        },
        keep_headers = {
            type = "boolean",
            title = "whether to keep the http request header",
            default = false,
        },
        validate_body = {
            type = "boolean",
            title = "whether to validate the http request body",
            default = false,
        },
        encode_uri_params = {
            type = "boolean",
            title = "Whether to escape the uri parameter",
            default = true,
        }
    },
    required = {"access_key", "secret_key"},
    additionalProperties = false,
}

local _M = {
    version = 0.1,
    priority = 2540,
    type = 'auth',
    name = plugin_name,
    schema = schema,
    consumer_schema = consumer_schema
}

local hmac_funcs = {
    ["hmac-sha1"] = function(secret_key, message)
        return hmac_sha1(secret_key, message)
    end,
    ["hmac-sha256"] = function(secret_key, message)
        return hmac:new(secret_key, hmac.ALGOS.SHA256):final(message)
    end,
    ["hmac-sha512"] = function(secret_key, message)
        return hmac:new(secret_key, hmac.ALGOS.SHA512):final(message)
    end,
}


local function array_to_map(arr)
    local map = core.table.new(0, #arr)
    for _, v in ipairs(arr) do
      map[v] = true
    end

    return map
end


local function remove_headers(ctx, ...)
    local headers = { ... }
    if headers and #headers > 0 then
        for _, header in ipairs(headers) do
            core.log.info("remove_header: ", header)
            core.request.set_header(ctx, header, nil)
        end
    end
end


local create_consumer_cache
do
    local consumer_names = {}

    function create_consumer_cache(consumers)
        core.table.clear(consumer_names)

        for _, consumer in ipairs(consumers.nodes) do
            core.log.info("consumer node: ", core.json.delay_encode(consumer))
            consumer_names[consumer.auth_conf.access_key] = consumer
        end

        return consumer_names
    end

end -- do


function _M.check_schema(conf, schema_type)
    core.log.info("input conf: ", core.json.delay_encode(conf))

    if schema_type == core.schema.TYPE_CONSUMER then
        return core.schema.check(consumer_schema, conf)
    else
        return core.schema.check(schema, conf)
    end
end


local function get_consumer(access_key)
    if not access_key then
        return nil, {message = "missing access key"}
    end

    local consumer_conf = consumer.plugin(plugin_name)
    if not consumer_conf then
        return nil, {message = "Missing related consumer"}
    end

    local consumers = lrucache("consumers_key", consumer_conf.conf_version,
        create_consumer_cache, consumer_conf)

    local consumer = consumers[access_key]
    if not consumer then
        return nil, {message = "Invalid access key"}
    end

    return consumer
end


local function get_conf_field(access_key, field_name)
    local consumer, err = get_consumer(access_key)
    if err then
        return false, err
    end

    return consumer.auth_conf[field_name]
end


local function do_nothing(v)
    return v
end

local function validate_body(ctx, params)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()

    local digest_received = params.digest
    if not digest_received then
    -- if there is no digest and no body, it is ok
        return body == ""
    end

    local digest = resty_sha256:new()
    digest:update(body or '')
    local digest_created = "SHA-256=" .. ngx_encode_base64(digest:final())

    return digest_created == digest_received
end

local function create_hash(ctx, request_uri, params)
  local signing_string = ""
  local hmac_headers = ngx_re.split(params.signed_headers, ' ')

  local count = #hmac_headers
  for i = 1, count do
    local header = hmac_headers[i]
    local header_value = core.request.header(ctx, header)

    if not header_value then
      if header == "@request-target" then
        local request_target = string_lower(kong.request.get_method()) .. " " .. request_uri
        signing_string = signing_string .. header .. ": " .. request_target

      elseif header == "request-line" then
        -- request-line in hmac headers list
        local request_line = fmt("%s %s HTTP/%.01f",
                                 kong_request.get_method(),
                                 request_uri,
                                 assert(kong_request.get_http_version()))
        signing_string = signing_string .. request_line

      else
        signing_string = signing_string .. header .. ":"
      end

    else
      signing_string = signing_string .. header .. ":" .. " " .. header_value
    end

    if i < count then
      signing_string = signing_string .. "\n"
    end
  end

  return hmac_funcs[params.algorithm](params.secret_key, signing_string)
end

local function validate_signature(ctx, params)
--     local signature_1 = create_hash(ngx_req.get_path_with_query(), params)
    local signature_2 = ngx_decode_base64(params.signature)
--     if signature_1 == signature_2 then
--         return true
--     end

    local signature_1_deprecated = create_hash(ctx, ngx.var.uri, params)
    return signature_1_deprecated == signature_2
end

local function generate_signature(ctx, secret_key, params)
    local canonical_uri = ctx.var.uri
    local canonical_query_string = ""
    local request_method = ngx_req.get_method()
    local args = ngx_req.get_uri_args()

    if canonical_uri == "" then
        canonical_uri = "/"
    end

    if type(args) == "table" then
        local keys = {}
        local query_tab = {}

        for k, v in pairs(args) do
            core.table.insert(keys, k)
        end
        core.table.sort(keys)

        local field_val = get_conf_field(params.access_key, "encode_uri_params")
        core.log.info("encode_uri_params: ", field_val)

        local encode_or_not = do_nothing
        if field_val then
            encode_or_not = escape_uri
        end

        for _, key in pairs(keys) do
            local param = args[key]
            -- when args without `=<value>`, value is treated as true.
            -- In order to be compatible with args lacking `=<value>`,
            -- we need to replace true with an empty string.
            if type(param) == "boolean" then
                param = ""
            end

            -- whether to encode the uri parameters
            if type(param) == "table" then
                for _, val in pairs(param) do
                    core.table.insert(query_tab, encode_or_not(key) .. "=" .. encode_or_not(val))
                end
            else
                core.table.insert(query_tab, encode_or_not(key) .. "=" .. encode_or_not(param))
            end
        end
        canonical_query_string = core.table.concat(query_tab, "&")
    end

    core.log.info("all headers: ",
                  core.json.delay_encode(core.request.headers(ctx), true))

    local signing_string_items = {
        request_method,
        canonical_uri,
        canonical_query_string,
        params.access_key,
        params.date,
    }

    if params.signed_headers then
        for _, h in ipairs(params.signed_headers) do
            local canonical_header = core.request.header(ctx, h) or ""
            core.table.insert(signing_string_items,
                              h .. ":" .. canonical_header)
            core.log.info("canonical_header name:", core.json.delay_encode(h))
            core.log.info("canonical_header value: ",
                          core.json.delay_encode(canonical_header))
        end
    end

    local signing_string = core.table.concat(signing_string_items, "\n") .. "\n"

    return hmac_funcs[params.algorithm](secret_key, signing_string)
end


local function validate(ctx, params)
    if not params.access_key or not params.signature then
        return nil, {message = "access key or signature missing"}
    end

    local consumer, err = get_consumer(params.access_key)
    if err then
        return nil, err
    end
    -- 判断consumer所支持的算法和header中的是否一致
    local conf = consumer.auth_conf
    core.log.info("secret_key:", conf.secret_key)
    if conf.algorithm ~= params.algorithm then
        return nil, {message = "algorithm " .. params.algorithm .. " not supported"}
    end
    -- 判断请求时间是否不合法
    core.log.info("clock_skew: ", conf.clock_skew)
    if conf.clock_skew and conf.clock_skew > 0 then
        local time = ngx.parse_http_time(params.date)
        core.log.info("params.date: ", params.date, " time: ", time)
        if not time then
            return nil, {message = "Invalid GMT format time"}
        end

        local diff = abs(ngx_time() - time)
        core.log.info("gmt diff: ", diff)
        if diff > conf.clock_skew then
            return nil, {message = "Clock skew exceeded"}
        end
    end

    -- validate headers
    if conf.signed_headers and #conf.signed_headers >= 1 then
        local headers_map = array_to_map(conf.signed_headers)
        if params.signed_headers then
            for _, header in ipairs(params.signed_headers) do
                if not headers_map[header] then
                    return nil, {message = "Invalid signed header " .. header}
                end
            end
        end
    end

    local secret_key          = conf and conf.secret_key
    params.secret_key = secret_key
    local ok = validate_signature(ctx, params)
    if not ok then
        return nil, {message = "Invalid signature"}
    end

    return consumer
end


local function get_params(ctx)
    local params = {}
    local local_conf = core.config.local_conf()
    local access_key = ACCESS_KEY
    local digest_key = DIGEST_KEY
    local signature_key = SIGNATURE_KEY
    local date_key = DATE_KEY
    local algorithm_key = ALGORITHM_KEY
    local signed_headers = SIGNED_HEADERS_KEY

    local attr = core.table.try_read_attr(local_conf, "plugin_attr",
                                          "hmac-auth")
    if attr then
        access_key = attr.access_key or access_key
        digest_key = attr.digest_key or digest_key
        date_key = attr.date_key or date_key
    end

    local app_key = core.request.header(ctx, access_key)
    local digest = core.request.header(ctx, digest_key)
    local signature = core.request.header(ctx, signature_key)
    local date = core.request.header(ctx, date_key)
    local algorithm = core.request.header(ctx, algorithm_key)

    -- get params from header `Authorization`
    if not app_key then
        local auth_string = core.request.header(ctx, "Authorization")
        if not auth_string then
            core.log.info("err: Authorization is nil")
            return params
        end

        local auth_data = ngx_re.split(auth_string, ",")
        core.log.info("auth_string: ", auth_string, " #auth_data: ",
                      #auth_data, " auth_data: ",
                      core.json.delay_encode(auth_data))

        if #auth_data == 4 then
            app_key = ngx_re.split(auth_data[1], '"')[2]
            signature = ngx_re.split(auth_data[4], '"')[2]
            signed_headers = ngx_re.split(auth_data[3], '"')[2]
            algorithm = ngx_re.split(auth_data[2], '"')[2]
        end
    end

    params.access_key = app_key
    params.signature  = signature
    params.date  = date or ""
    params.digest = digest
    params.signed_headers = signed_headers
    params.algorithm = algorithm

    return params
end


function _M.rewrite(conf, ctx)
    local params = get_params(ctx)
    -- validate body or not
    if conf.validate_body then
        local validated_digest, err = validate_body(ctx, params)
        if err then
            return 401, err
        end

        if not validated_digest then
            return 401, {message = "Invalid body digest"}
        end
    end
    local validated_consumer, err = validate(ctx, params)
    if err then
        return 401, err
    end

    if not validated_consumer then
        return 401, {message = "Invalid signature"}
    end

    local consumer_conf = consumer.plugin(plugin_name)
    consumer.attach_consumer(ctx, validated_consumer, consumer_conf)
    --  添加consumer名称到头部
    core.request.set_header(ctx, "X-Client-Id", ctx.consumer_name)
    core.log.info("hit hmac-auth rewrite")
end


return _M
