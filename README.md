## APISIX 支持环境变量指定配置的 Docker 镜像

## 文件目录说明

```shell
.
├── auto_conf                  # 自动生成配置工具
│   ├── config-template.yaml   # JinJa2 配置模板
│   └── make_conf.py           # 配置生成脚本
├── docker-entrypoint.sh
├── Dockerfile
├── plugins
│   ├── kong-hmac.lua              # 从 KONG 网关移植的 HMAC 插件：https://zhang.ge/5159.html
│   ├── limit-count-by-client.lua  # 精细化限速插件：https://zhang.ge/5158.html
├── README.md
```

## 容器配置说明
所有`APISIX`中的配置都可以使用环境变量`apisix_xxxxxx`来指定，比如修改`APISIX`的`HTTP`监听端口为`80`，只需要在启动容器的时候指定`-e http_listen_port=80`即可，如果不满足只需要在模板文件中 [config-template.yaml](auto_conf/config-template.yaml) 修改即可。

更多帮助信息，请查阅文章说明：https://zhang.ge/5160.html
