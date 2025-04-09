#!/usr/bin/env python3

"""
配置管理模块
"""

import os
import threading
import configparser
from logger import LoggerManager

class ConfigManager:
    """配置管理类"""
    
    # 定义路径常量
    CONFIG_DIR = "/etc/safeline"
    KEY_FILE = f"{CONFIG_DIR}/token.key"
    TOKEN_FILE = f"{CONFIG_DIR}/token.enc"
    CONFIG_FILE = f"{CONFIG_DIR}/setting.conf"
    
    # 定义默认配置常量
    DEFAULT_CONFIG = {
        'GENERAL': {
            'SAFELINE_HOST': 'localhost',
            'SAFELINE_PORT': '9443',
            'HIGH_RISK_IP_GROUP': '黑名单',
            'LOW_RISK_IP_GROUP': '人机验证',
            'QUERY_INTERVAL': '60',
            'MAX_LOGS_PER_QUERY': '100',
            'LOG_RETENTION_DAYS': '30',
            'ATTACK_TYPES_FILTER': ''
        },
        'TYPE_GROUP_MAPPING': {
            '0': '黑名单',   # SQL注入
            '5': '黑名单',   # 后门
            '7': '黑名单',   # 代码执行
            '8': '黑名单',   # 代码注入
            '9': '黑名单',   # 命令注入
            '11': '黑名单',  # 文件包含
            '29': '黑名单',  # 模板注入
            '1': '人机验证', # XSS
            '2': '人机验证', # CSRF
            '3': '人机验证', # SSRF
            '4': '人机验证', # 拒绝服务
            '6': '人机验证', # 反序列化
            '10': '人机验证', # 文件上传
            '21': '人机验证'  # 扫描器
        }
    }
    
    @classmethod
    def get_path(cls, path_type):
        """获取指定类型的路径
        
        Args:
            path_type: 路径类型，可选值: 'key_file', 'token_file', 'config_file'
            
        Returns:
            str: 对应类型的路径
        """
        path_mapping = {
            'key_file': cls.KEY_FILE,
            'token_file': cls.TOKEN_FILE,
            'config_file': cls.CONFIG_FILE
        }
        return path_mapping.get(path_type)
    
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls):
        """获取配置管理器实例（线程安全）"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls.__new__(cls)
                    cls._instance._init_instance()
        return cls._instance

    def __init__(self):
            """初始化配置管理器"""
            self.logger = LoggerManager.get_instance().get_logger()
            self._config = None
            self.load()

    def _validate_and_repair_config(self, config):
        is_modified = False
        
        # 检查并补充所有配置
        for section, options in self.DEFAULT_CONFIG.items():
            if not config.has_section(section):
                config.add_section(section)
                is_modified = True
            for option, value in options.items():
                if not config.has_option(section, option):
                    config.set(section, option, str(value))
                    is_modified = True
        
        if is_modified:
            with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                config.write(f)
        
        return is_modified

    def create_default_config(self):
        """创建默认配置文件"""
        if os.path.exists(self.CONFIG_FILE):
            return False
        
        return self.set_value(self.DEFAULT_CONFIG)
    
    def load(self):
        """加载配置文件"""
        config = configparser.ConfigParser()
        
        try:
            if not os.path.exists(self.CONFIG_FILE):
                if not self.create_default_config():
                    return False
                config.read(self.CONFIG_FILE)
            else:
                config.read(self.CONFIG_FILE)
                if self._validate_and_repair_config(config):
                    config.read(self.CONFIG_FILE)
            
            self._config = config
            return True
            
        except Exception as error:
            self.logger.error(f"读取配置文件时出错: {str(error)}")
            return False

    def get_value(self, section, option):
        """获取配置项的值
        
        Args:
            section: 配置段名称
            option: 配置项名称
            
        Returns:
            配置值
        """
        try:
            value = self._config.get(section, option)
            
            if option in {'SAFELINE_PORT', 'QUERY_INTERVAL', 'MAX_LOGS_PER_QUERY', 'LOG_RETENTION_DAYS'}:
                return int(value)
            return value
                
        except Exception as error:
            self.logger.error(f"获取配置项 {section}.{option} 时出错: {error}")
            raise

    def set_value(self, section, option, value=None):
        try:
            config_data = section if isinstance(section, dict) else {section: {option: value}}
            
            # 更新配置
            modified = False
            for sec, options in config_data.items():
                if not self._config.has_section(sec):
                    self._config.add_section(sec)
                    modified = True
                for opt, val in options.items():
                    current_val = self._config.get(sec, opt, fallback=None)
                    if current_val != str(val):
                        self._config.set(sec, opt, str(val))
                        modified = True
            
            if modified:
                os.makedirs(os.path.dirname(self.CONFIG_FILE), exist_ok=True)
                with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                    self._config.write(f)
            
            return True
            
        except Exception as error:
            self.logger.error(f"更新配置失败: {error}")
            return False

    def get_token(self):
        try:
            # 直接使用类常量
            if not os.path.exists(self.TOKEN_FILE):
                self.logger.error(f"令牌文件不存在: {self.TOKEN_FILE}")
                return None
            
            with open(self.TOKEN_FILE, 'r') as token_file:
                encrypted_token = token_file.read().strip()
            
            # 从密钥文件读取密钥
            if not os.path.exists(self.KEY_FILE):
                self.logger.error(f"密钥文件不存在: {self.KEY_FILE}")
                return None
            
            with open(self.KEY_FILE, 'r') as key_file:
                key = key_file.read().strip()
            
            # 解密令牌
            from cryptography.fernet import Fernet
            fernet = Fernet(key.encode())
            return fernet.decrypt(encrypted_token.encode()).decode()
            
        except Exception as error:
            self.logger.error(f"解密令牌失败: {error}")
            return None

    def update_token(self, new_token):
        try:
            with open(self.KEY_FILE, 'r') as key_file:
                key = key_file.read().strip()
            
            from cryptography.fernet import Fernet
            fernet = Fernet(key.encode())
            encrypted_token = fernet.encrypt(new_token.encode()).decode()
            
            with open(self.TOKEN_FILE, 'w') as token_file:
                token_file.write(encrypted_token)
            
            return True
            
        except Exception as error:
            self.logger.error(f"更新令牌失败: {error}")
            return False
