#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置管理模块
"""

import os
import sys
import configparser
import logging

# 定义路径常量
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, 'auto_blocker.conf')
KEY_FILE = os.path.join(SCRIPT_DIR, '.key')
LOG_DIR = os.path.join(SCRIPT_DIR, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'auto_blocker.log')

# 安装相关路径 - 保持Linux路径风格
INSTALL_DIR = '/opt/safeline/scripts'
CONFIG_DIR = '/etc/safeline'
INSTALL_LOG_DIR = '/var/log/safeline'
SERVICE_FILE = '/etc/systemd/system/safeline-auto-blocker.service'

# 集中定义所有路径
PATHS = {
    'SCRIPT_DIR': SCRIPT_DIR,
    'CONFIG_FILE': CONFIG_FILE,
    'KEY_FILE': KEY_FILE,
    'LOG_DIR': LOG_DIR,
    'LOG_FILE': LOG_FILE,
    'INSTALL_DIR': INSTALL_DIR,
    'CONFIG_DIR': CONFIG_DIR,
    'INSTALL_LOG_DIR': INSTALL_LOG_DIR,
    'SERVICE_FILE': SERVICE_FILE,
    'INSTALL_CONFIG_FILE': os.path.join(CONFIG_DIR, 'auto_blocker.conf'),
    'INSTALL_KEY_FILE': os.path.join(CONFIG_DIR, '.key'),
    'INSTALL_CONFIG_EXAMPLE': os.path.join(CONFIG_DIR, 'auto_blocker.conf.example'),
    'INSTALL_LOG_FILE': os.path.join(INSTALL_LOG_DIR, 'auto_blocker.log'),  # 添加安装日志文件路径
    'SCRIPT_FILES': [
        os.path.join(INSTALL_DIR, 'safeline_auto_blocker.py'),
        os.path.join(INSTALL_DIR, 'api.py'),
        os.path.join(INSTALL_DIR, 'config.py'),
        os.path.join(INSTALL_DIR, 'logger.py'),
        os.path.join(INSTALL_DIR, 'uninstall_auto_blocker.py')
    ]
}

# 导入日志管理器（修复导入顺序）
from logger import logger_manager
# 获取日志记录器
logger = logger_manager.get_logger()

def parse_config(config_file=None, logger_instance=None):
    """解析配置文件"""
    # 使用有效的配置文件路径
    config_file = config_file or get_effective_config_file()
    
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

# 在文件末尾添加
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

def get_effective_key_file():
    """获取当前环境下有效的密钥文件路径"""
    if is_installed_environment():
        return PATHS['INSTALL_KEY_FILE']
    else:
        return KEY_FILE

# 读取密钥
try:
    key_file_path = get_effective_key_file()
    with open(key_file_path, 'r') as key_file:
        key = key_file.read().strip()
except Exception as error:
    logger.error(f"读取密钥文件时出错: {str(error)}")
    key = None

def is_installed_environment():
    """检查当前是否在安装环境中运行"""
    return os.path.exists(INSTALL_DIR) and os.path.isdir(INSTALL_DIR)

def get_effective_config_file():
    """获取当前环境下有效的配置文件路径"""
    if is_installed_environment():
        return PATHS['INSTALL_CONFIG_FILE']
    else:
        return CONFIG_FILE
