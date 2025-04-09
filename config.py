#!/usr/bin/env python3

"""
配置管理模块
"""

import os
import sys
import logging
import configparser

# 定义路径常量
CONFIG_DIR = "/etc/safeline"
KEY_FILE = "$CONFIG_DIR/token.key"
TOKEN_FILE = "$CONFIG_DIR/token.enc"
CONFIG_FILE = "$CONFIG_DIR/setting.conf"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, 'logs')
LOG_FILE = os.path.join(LOG_DIR, 'autoblocker.log')

def get_key_file():
    return KEY_FILE

def get_token_file():
    return TOKEN_FILE

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
        'SAFELINE_HOST': {
            'type': str,
            'default': 'localhost',
            'required': True
        },
        'SAFELINE_PORT': {
            'type': int,
            'default': 9443,
            'required': True
        },
        'HIGH_RISK_IP_GROUP': {
            'type': str,
            'default': '黑名单',
            'required': True
        },
        'LOW_RISK_IP_GROUP': {
            'type': str,
            'default': '人机验证',
            'required': True
        },
        'QUERY_INTERVAL': {
            'type': int,
            'default': 60,
            'required': False
        },
        'MAX_LOGS_PER_QUERY': {
            'type': int,
            'default': 100,
            'required': False
        },
        'LOG_RETENTION_DAYS': {
            'type': int,
            'default': 30,
            'required': False
        },
        'ATTACK_TYPES_FILTER': {
            'type': str,
            'default': '',
            'required': False
        }
    },
    'TYPE_GROUP_MAPPING': {
        # 这部分保持不变
    }
}

# 修改create_default_config函数
def create_default_config(config_file=None, logger_instance=None):
    """创建默认配置文件"""
    # 使用有效的配置文件路径
    config_file = config_file or get_effective_config_file()
    
    # 使用日志管理器获取日志记录器
    logger_to_use = logger_instance or logger_manager.get_logger()
    
    # 默认配置 - 使用常量而非硬编码值
    default_config = {
        'DEFAULT': {
            'SAFELINE_HOST': 'localhost',
            'SAFELINE_PORT': '9443',
            'TOKEN': '/etc/safeline/token.key',
            'HIGH_RISK_IP_GROUP': '黑名单',
            'LOW_RISK_IP_GROUP': '人机验证',
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
    """解密令牌
    
    Args:
        encrypted_token: 加密的令牌字符串
        key: 解密密钥
        
    Returns:
        str: 解密后的令牌
    """
    from cryptography.fernet import Fernet
    
    try:
        fernet = Fernet(key.encode())
        decrypted_token = fernet.decrypt(encrypted_token.encode()).decode()
        return decrypted_token
    except Exception as error:
        logger.error(f"解密令牌失败: {error}")
        raise
