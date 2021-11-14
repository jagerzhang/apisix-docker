FROM apache/apisix:2.10.0-centos
LABEL maintainer="Jager", description="支持环境变量设置任意配置的APISIX镜像。"

RUN yum install -y python-jinja2

COPY plugins /usr/local/apisix/apisix/plugins

COPY auto_conf /opt/auto_conf

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/local/openresty/bin/openresty", "-p", "/usr/local/apisix", "-g", "daemon off;"]
