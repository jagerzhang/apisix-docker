FROM apache/apisix:2.10.0-centos
LABEL maintainer="Jager", description="支持从七彩石拉取配置的APISIX镜像"

RUN yum install -y python-requests python-jinja2 net-tools bind-utils

COPY plugins /usr/local/apisix/apisix/plugins

COPY auto_conf /opt/auto_conf

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["/usr/local/openresty/bin/openresty", "-p", "/usr/local/apisix", "-g", "daemon off;"]
