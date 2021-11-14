## APISIX Docker镜像构建配置

## 文件目录说明

```shell
.
├── auto_conf                  # 自动生成配置工具
│   ├── config-template.yaml   # JinJa2 配置模板
│   └── make_conf.py            # 配置生成脚本
├── build.yaml
├── discovery
│   └── polaris.lua
├── docker-entrypoint.sh
├── Dockerfile
├── Dockerfile_base
├── plugins
│   ├── kong-hmac.lua
│   ├── limit-count-by-client.lua
│   ├── trpc-transcode
│   └── trpc-transcode.lua
├── README.md
└── utils                       # TAPISIX 北极星库
    ├── libpolaris_api.so
    └── polaris_client.lua
```

## 容器配置说明
七彩石配置直接沿用官方配置参数名, 可能会出现冲突的参数名称会在前面加上本参数的上一级节点前缀, 详见`config-template.yaml`文件内容.

本地配置则在参数名称前面加上了`ngate_`前缀, 方便快速获取.
