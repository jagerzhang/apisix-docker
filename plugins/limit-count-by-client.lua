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
local limit_local_new = require("resty.limit.count").new
local core = require("apisix.core")
local plugin_name = "limit-count-by-client"
local limit_redis_cluster_new
local limit_redis_new
do
    local redis_src = "apisix.plugins.limit-count.limit-count-redis"
    limit_redis_new = require(redis_src).new

    local cluster_src = "apisix.plugins.limit-count.limit-count-redis-cluster"
    limit_redis_cluster_new = require(cluster_src).new
end
local lrucache = core.lrucache.new({
    type = 'plugin', serial_creating = true,
})


local schema = {
    type = "object",
    properties = {
        key = {
            type = "string",
            enum = {"remote_addr", "server_addr", "http_x_real_ip",
                    "http_x_forwarded_for", "consumer_name"},
            default = "remote_addr",
        },
        default_count = {type = "integer", exclusiveMinimum = 0},
        default_time_window = {type = "integer",  exclusiveMinimum = 0},
        scope = {
            type = "string",
            enum = {"route_id", "service_id"},
            default = "route_id",
        },
        map = {
            type = "object",
            items = {
                type = "object",
                count = {type = "integer", exclusiveMinimum = 0},
                time_window = {type = "integer",  exclusiveMinimum = 0},
            }
        },
        rejected_code = {
            type = "integer", minimum = 200, maximum = 599, default = 429
        },
        error_interrupt = {type = "boolean", default = false},
        policy = {
            type = "string",
            enum = {"local", "redis", "redis-cluster"},
            default = "local",
        }
    },
    dependencies = {
        policy = {
            oneOf = {
                {
                    properties = {
                        policy = {
                            enum = {"local"},
                        },
                    },
                },
                {
                    properties = {
                        policy = {
                            enum = {"redis"},
                        },
                        redis_host = {
                            type = "string", minLength = 2
                        },
                        redis_port = {
                            type = "integer", minimum = 1, default = 6379,
                        },
                        redis_password = {
                            type = "string", minLength = 0,
                        },
                        redis_database = {
                            type = "integer", minimum = 0, default = 0,
                        },
                        redis_timeout = {
                            type = "integer", minimum = 1, default = 2000,
                        },
                    },
                    required = {"redis_host"},
                },
                {
                    properties = {
                        policy = {
                            enum = {"redis-cluster"},
                        },
                        redis_cluster_nodes = {
                            type = "array",
                            minItems = 2,
                            items = {
                                type = "string", minLength = 2, maxLength = 100
                            },
                        },
                        redis_password = {
                            type = "string", minLength = 0,
                        },
                        redis_timeout = {
                            type = "integer", minimum = 1, default = 1000,
                        },
                        redis_cluster_name = {
                            type = "string",
                        },
                    },
                    required = {"redis_cluster_nodes", "redis_cluster_name"},
                }
            }
        }
    }
}


local _M = {
    version = 0.4,
    priority = 1002,
    name = plugin_name,
    schema = schema,
}


function _M.check_schema(conf)
    local ok, err = core.schema.check(schema, conf)
    if not ok then
        return false, err
    end

    return true
end


local function create_limit_obj(conf, ctx)
    core.log.info("create new limit-count plugin instance")
    
    local req_key = ctx.var[conf.key]
    local item_count = 0
    local item_time_window = 0
    if conf.map[req_key] ~= nil then
        item_count = conf.map[req_key].count
        item_time_window = conf.map[req_key].time_window
    else
        item_count = conf.default_count
        item_time_window = conf.default_time_window

    end

    if not conf.policy or conf.policy == "local" then
        return limit_local_new("plugin-" .. plugin_name, item_count,
                               item_time_window)
    end

    if conf.policy == "redis" then
        return limit_redis_new("plugin-" .. plugin_name,
                               item_count, item_time_window, conf)
    end

    if conf.policy == "redis-cluster" then
        return limit_redis_cluster_new("plugin-" .. plugin_name, item_count,
                                       item_time_window, conf)
    end

    return nil
end


function _M.access(conf, ctx)
    core.log.info("ver: ", ctx.conf_version)
    local lim, err = core.lrucache.plugin_ctx(lrucache, ctx, conf.policy, create_limit_obj, conf, ctx)

    if lim then
        local req_key = ctx.var[conf.key]
        local limit_key = req_key .. conf.scope
        local key = (limit_key or "") .. ctx.conf_type .. ctx.conf_version
        core.log.info("limit key: ", key)

        local delay, remaining = lim:incoming(key, true)
        if not delay then
            local err = remaining
            if err == "rejected" then
                return conf.rejected_code
            end

            core.log.error("failed to limit count: ", err)
            if conf.error_interrupt then
                return 500, {error_msg = "failed to limit count, please contact the administrator: " .. err}
            end
        end
        local item_count = 0
        local item_time_window = 0
        if conf.map[req_key] ~= nil then
            item_count = conf.map[req_key].count
        else
            item_count = conf.default_count

        end
        core.response.set_header("X-RateLimit-Limit", item_count,
                                "X-RateLimit-Remaining", remaining)
    else
        core.log.error("failed to fetch limit.count object: ", err)
        if conf.error_interrupt then
            return 500, {error_msg = "failed to limit count, please contact the administrator: " .. err}
        end
    end
end


return _M
