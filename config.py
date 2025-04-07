#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置管理模块
"""

import os
import sys
import configparser
import logging

# 定义路径常量 - 移除安装环境相关的路径
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, 'setting.conf')
KEY_FILE = os.path.join(SCRIPT_DIR, 'token.key')
LOG_DIR = os.path.join(SCRIPT_DIR, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'autoblocker.log')

def get_key_file():
    return KEY_FILE

def get_config_file():
    return CONFIG_FILE

def get_log_dir():
    return LOG_DIR

def get_log_file():
    return os.path.join(LOG_DIR, LOG_FILE)

# 导入日志管理器
from logger import logger_manager
# 获取日志记录器
logger = logger_manager.get_logger()

def parse_config(config_file=None, logger_instance=None):
    """解析配置文件"""
    # 使用传入的配置文件路径或默认路径
    config_file = config_file or CONFIG_FILE
    
    # 使用日志管理器获取日志记录器
    logger_to_use = logger_instance or logger_manager.get_logger()
    
    config = configparser.ConfigParser()
    
    if not os.path.exists(config_file):
        logger_to_use.error(f"配置文件不存在: {config_file}")
        return None
    
    try:
        config.read(config_file)
        return config
    except Exception as error:
        logger_to_use.error(f"读取配置文件时出错: {str(error)}")
        return None

# 定义配置项验证规则
CONFIG_SCHEMA = {
    'DEFAULT': {
        'HOST': {
            'required': True,
            'type': str,
            'validator': lambda x: len(x) > 0
        },
        'PORT': {
            'required': True,
            'type': int,
            'validator': lambda x: 1 <= x <= 65535,
            'error_msg': '端口必须在1-65535之间'
        },
        'TOKEN': {
            'required': True,
            'type': str,
            'validator': lambda x: len(x) > 0,
            'error_msg': 'API令牌不能为空'
        },
        'DEFAULT_IP_GROUP': {
            'required': True,
            'type': str,
            'validator': lambda x: len(x) > 0,
            'error_msg': '默认IP组名称不能为空'
        },
        'QUERY_INTERVAL': {
            'required': True,
            'type': int,
            'validator': lambda x: x >= 5,
            'error_msg': '查询间隔必须大于等于5秒'
        },
        'MAX_LOGS_PER_QUERY': {
            'required': True,
            'type': int,
            'validator': lambda x: x > 0,
            'error_msg': '每次查询的最大日志数必须大于0'
        },
        'LOG_RETENTION_DAYS': {
            'required': False,
            'type': int,
            'validator': lambda x: x >= 0,
            'error_msg': '日志保留天数必须大于等于0',
            'default': 30
        },
        'USE_TYPE_GROUPS': {
            'required': False,
            'type': bool,
            'default': False
        }
    },
    'TYPE_GROUP_MAPPING': {
        # 这个部分是可选的，不需要特定的验证规则
    }
}

def validate_config(config, logger_instance=None):
    """验证配置有效性"""
    # 使用日志管理器获取日志记录器
    logger_to_use = logger_instance or logger_manager.get_logger()
    
    # 验证结果
    is_valid = True
    errors = []
    
    # 验证必需的部分
    for section, fields in CONFIG_SCHEMA.items():
        if section not in config:
            if section == 'DEFAULT':
                errors.append(f"缺少必需的配置部分: {section}")
                is_valid = False
                continue
            else:
                # 非DEFAULT部分是可选的
                continue
        
        # 验证每个字段
        for field_name, rules in fields.items():
            # 检查必需字段
            if rules.get('required', False) and not config.has_option(section, field_name):
                errors.append(f"缺少必需的配置项: {section}.{field_name}")
                is_valid = False
                continue
            
            # 如果字段存在，验证其值
            if config.has_option(section, field_name):
                try:
                    # 根据类型获取值
                    if rules.get('type') == int:
                        value = config.getint(section, field_name)
                    elif rules.get('type') == bool:
                        value = config.getboolean(section, field_name)
                    elif rules.get('type') == float:
                        value = config.getfloat(section, field_name)
                    else:
                        value = config.get(section, field_name)
                    
                    # 应用验证器
                    if 'validator' in rules and not rules['validator'](value):
                        errors.append(f"配置项 {section}.{field_name} 无效: {rules['error_msg']}")
                        is_valid = False
                except (ValueError, TypeError) as e:
                    errors.append(f"配置项 {section}.{field_name} 类型错误: {str(e)}")
                    is_valid = False
    
    # 特殊验证：如果启用了类型组，验证映射
    if config.has_option('DEFAULT', 'USE_TYPE_GROUPS') and config.getboolean('DEFAULT', 'USE_TYPE_GROUPS'):
        if 'TYPE_GROUP_MAPPING' not in config:
            errors.append("启用了攻击类型组映射，但缺少 TYPE_GROUP_MAPPING 部分")
            is_valid = False
        elif len(config['TYPE_GROUP_MAPPING']) == 0:
            errors.append("启用了攻击类型组映射，但 TYPE_GROUP_MAPPING 部分为空")
            is_valid = False
    
    # 输出验证结果
    if not is_valid:
        for error in errors:
            logger_to_use.error(error)
        logger_to_use.error("配置验证失败，请检查配置文件")
    else:
        logger_to_use.info("配置验证通过")
    
    return is_valid

def get_config_values(config):
    """从配置对象中提取配置值"""
    config_values = {}
    
    # 提取基本配置
    for section, fields in CONFIG_SCHEMA.items():
        for field_name, rules in fields.items():
            # 转换为小写键名
            key_name = field_name.lower()
            
            # 如果配置项存在
            if config.has_option(section, field_name):
                try:
                    # 根据类型获取值
                    if rules.get('type') == int:
                        config_values[key_name] = config.getint(section, field_name)
                    elif rules.get('type') == bool:
                        config_values[key_name] = config.getboolean(section, field_name)
                    elif rules.get('type') == float:
                        config_values[key_name] = config.getfloat(section, field_name)
                    else:
                        config_values[key_name] = config.get(section, field_name)
                except (ValueError, TypeError):
                    # 如果转换失败，使用默认值
                    if 'default' in rules:
                        config_values[key_name] = rules['default']
            # 如果配置项不存在但有默认值
            elif 'default' in rules:
                config_values[key_name] = rules['default']
    
    # 处理类型组映射
    if 'use_type_groups' in config_values and config_values['use_type_groups'] and 'TYPE_GROUP_MAPPING' in config:
        type_group_mapping = {}
        for attack_type, group_name in config['TYPE_GROUP_MAPPING'].items():
            type_group_mapping[attack_type] = group_name
        config_values['type_group_mapping'] = type_group_mapping
    else:
        config_values['type_group_mapping'] = {}
    
    # 处理攻击类型过滤
    if config.has_option('DEFAULT', 'ATTACK_TYPES_FILTER'):
        filter_str = config.get('DEFAULT', 'ATTACK_TYPES_FILTER')
        if filter_str:
            config_values['attack_types_filter'] = [x.strip() for x in filter_str.split(',') if x.strip()]
        else:
            config_values['attack_types_filter'] = None
    else:
        config_values['attack_types_filter'] = None
    
    return config_values

def reload_config(config_file=None, logger_instance=None):
    """重新加载配置文件"""
    # 使用有效的配置文件路径
    config_file = config_file or get_effective_config_file()
    
    # 使用日志管理器获取日志记录器
    logger_to_use = logger_instance or logger_manager.get_logger()
    
    try:
        new_config = parse_config(config_file, logger_to_use)
        if new_config:
            # 验证配置有效性
            if validate_config(new_config, logger_to_use):
                logger_to_use.debug("配置文件已重新加载并通过验证")
                return new_config
            else:
                logger_to_use.error("配置文件验证失败，使用原有配置")
        else:
            logger_to_use.error("无法解析配置文件，使用原有配置")
    except Exception as error:
        logger_to_use.error(f"重新加载配置文件时出错: {str(error)}")
        return None

# 添加修改配置的函数
def update_config(config_updates, config_file=None, logger_instance=None):
    """更新配置文件
    
    Args:
        config_updates: 字典，包含要更新的配置项，格式为 {'section': {'option': 'value'}}
        config_file: 配置文件路径，默认使用当前环境的配置文件
        logger_instance: 日志记录器实例
        
    Returns:
        bool: 更新是否成功
    """
    # 使用有效的配置文件路径
    config_file = config_file or get_effective_config_file()
    
    # 使用日志管理器获取日志记录器
    logger_to_use = logger_instance or logger_manager.get_logger()
    
    try:
        # 读取当前配置
        config = configparser.ConfigParser()
        if os.path.exists(config_file):
            config.read(config_file)
        
        # 应用更新
        for section, options in config_updates.items():
            if section not in config:
                config[section] = {}
            for option, value in options.items():
                config[section][option] = str(value)
        
        # 保存配置
        with open(config_file, 'w') as f:
            config.write(f)
        
        logger_to_use.info(f"配置文件已更新: {config_file}")
        
        # 验证新配置
        new_config = parse_config(config_file, logger_to_use)
        if new_config and validate_config(new_config, logger_to_use):
            return True
        else:
            logger_to_use.error("更新后的配置验证失败")
            return False
            
    except Exception as error:
        logger_to_use.error(f"更新配置文件时出错: {str(error)}")
        return False

def create_default_config(config_file=None, logger_instance=None):
    """创建默认配置文件"""
    # 使用有效的配置文件路径
    config_file = config_file or get_effective_config_file()
    
    # 使用日志管理器获取日志记录器
    logger_to_use = logger_instance or logger_manager.get_logger()
    
    # 默认配置 - 使用常量而非硬编码值
    default_config = {
        'DEFAULT': {
            'HOST': 'localhost',
            'PORT': '9443',
            'TOKEN': '',  # 需要在安装时设置
            'DEFAULT_IP_GROUP': '人机验证',
            'USE_TYPE_GROUPS': 'true',
            'QUERY_INTERVAL': '60',
            'MAX_LOGS_PER_QUERY': '100',
            'LOG_RETENTION_DAYS': '30',
            'CONFIG_RELOAD_INTERVAL': str(CONFIG_RELOAD_INTERVAL),
            'ATTACK_TYPES_FILTER': ''
        },
        'TYPE_GROUP_MAPPING': {
            '0': '黑名单',  # SQL注入
            '5': '黑名单',  # 后门
            '7': '黑名单',  # 代码执行
            '8': '黑名单',  # 代码注入
            '9': '黑名单',  # 命令注入
            '11': '黑名单', # 文件包含
            '29': '黑名单', # 模板注入
            '1': '人机验证',  # XSS
            '2': '人机验证',  # CSRF
            '3': '人机验证',  # SSRF
            '4': '人机验证',  # 拒绝服务
            '6': '人机验证',  # 反序列化
            '10': '人机验证', # 文件上传
            '21': '人机验证'  # 扫描器
        }
    }
    
    return update_config(default_config, config_file, logger_to_use)

def decrypt_token(encrypted_token, key):
    """解密令牌"""
    try:
        # 创建Fernet实例
        from cryptography.fernet import Fernet
        fernet = Fernet(key.encode())  # 修改: f -> fernet
        
        # 解密令牌
        decrypted_token = fernet.decrypt(encrypted_token.encode()).decode()
        return decrypted_token
    except Exception as error:
        raise Exception(f"解密令牌失败: {str(error)}")
