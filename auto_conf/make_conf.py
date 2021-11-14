# -*- coding:utf-8 -*-
"""APISIX 配置文件生成工具
功能描述：通过获取环境变量生成APISIX的配置文件。
"""
import sys
import os
import requests
from jinja2 import Environment, FileSystemLoader
reload(sys)
sys.setdefaultencoding('utf-8')


class Utils():
    def __init__(self):
        self.path = os.path.dirname(os.path.abspath(__file__))
        self.template_environment = Environment(
            autoescape=False,
            loader=FileSystemLoader(os.path.join(self.path, '')),
            trim_blocks=False)

    def render_template(self, template_filename, context):
        return self.template_environment.get_template(
            template_filename).render(context)

    def gen_yaml_content(self, template, context):
        yaml = self.render_template(template, context)
        return yaml

    def get_env_list(self, prefix=None, replace=True):
        """ 获取环境变量
            :param prefix： 指定目标变量的前缀
            :param replace：指定前缀后，键名是否去掉前缀
        """
        env_dict = os.environ

        if prefix:
            env_list = {}
            for key in env_dict:
                if prefix in key:
                    if replace:
                        env_list[key.replace(prefix, "")] = env_dict[key]
                    else:
                        env_list[key] = env_dict[key]

            return env_list

        else:
            return dict(env_dict)


if __name__ == "__main__":
    utils = Utils()

    try:
        config_list = utils.get_env_list(prefix="apisix_")
        content = utils.gen_yaml_content("config-template.yaml", config_list)

        with open("/usr/local/apisix/conf/config.yaml", "w") as f:
            f.write(content)

    except Exception as error:  # pylint: disable=broad-except
        exit("Failed to generate configuration file: {}".format(error))
