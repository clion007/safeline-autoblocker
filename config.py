#!/usr/bin/env python3

"""
配置管理模块
"""

import os
import configparser
from logger import get_logger_manager

class ConfigManager:
    """配置管理类"""
    
    # 定义路径常量
    CONFIG_DIR = "/etc/safeline"
    KEY_FILE = f"{CONFIG_DIR}/token.key"
    TOKEN_FILE = f"{CONFIG_DIR}/token.enc"
    CONFIG_FILE = f"{CONFIG_DIR}/setting.conf"
    LOG_DIR = "logs"
    LOG_FILE = "logs/autoblocker.log"
    
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
            path_type: 路径类型，可选值: 'key_file', 'token_file', 'config_file', 'log_dir', 'log_file'
            
        Returns:
            str: 对应类型的路径
        """
        path_mapping = {
            'key_file': cls.KEY_FILE,
            'token_file': cls.TOKEN_FILE,
            'config_file': cls.CONFIG_FILE,
            'log_dir': cls.LOG_DIR,
            'log_file': cls.LOG_FILE
        }
        return path_mapping.get(path_type)
    
    def __init__(self):
        """初始化配置管理器"""
        self.logger = get_logger_manager().get_logger()
        self._config = None
        # 初始化时自动加载配置
        self.load()
    
    def _validate_and_repair_config(self, config):
        is_modified = False
        
        # 检查并补充所有配置
        for section, options in self.DEFAULT_CONFIG.items():
            # 修正：为 GENERAL 段创建配置
            if section == 'GENERAL':
                if not config.has_section(section):
                    config.add_section(section)
                    is_modified = True
                for option, value in options.items():
                    if not config.has_option(section, option):
                        config.set(section, option, str(value))
                        is_modified = True
            else:
                if section not in config.sections():
                    config.add_section(section)
                    is_modified = True
                for option, value in options.items():
                    if not config.has_option(section, option):
                        config.set(section, option, str(value))
                        is_modified = True
        
        if is_modified:
            self.logger.warning("配置文件不完整，已自动补充缺失配置")
            with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                config.write(f)
        
        return True

    def create_default_config(self):
        """创建默认配置文件"""
        if os.path.exists(self.CONFIG_FILE):
            self.logger.warning(f"配置文件已存在: {self.CONFIG_FILE}")
            return False
        
        return self.set_value(self.DEFAULT_CONFIG)
    
    def load(self):
        """加载配置文件"""
        config = configparser.ConfigParser()
        
        try:
            if not os.path.exists(self.CONFIG_FILE):
                self.logger.warning(f"配置文件不存在，创建默认配置: {self.CONFIG_FILE}")
                if not self.create_default_config():
                    return False
        
            config.read(self.CONFIG_FILE)
            # 验证并修复配置
            self._validate_and_repair_config(config)
            
            self._config = config
            return True
            
        except Exception as error:
            self.logger.error(f"读取配置文件时出错: {str(error)}")
            self.logger.warning("尝试重新创建默认配置")
            if not self.create_default_config():
                return False
            return self.load()
    
    def get_value(self, section, option):
        """获取配置项的值
        
        Args:
            section: 配置段名称
            option: 配置项名称
            
        Returns:
            配置值
        """
        try:
            # 获取配置值
            if section == 'GENERAL':
                value = self._config.get('GENERAL', option)  # 直接从 GENERAL 段获取
            else:
                value = self._config.get(section, option)
            
            # 根据配置项进行类型转换
            if option in {'SAFELINE_PORT', 'QUERY_INTERVAL', 'MAX_LOGS_PER_QUERY', 'LOG_RETENTION_DAYS'}:
                return int(value)
            return value
                
        except Exception as error:
            self.logger.error(f"获取配置项 {section}.{option} 时出错: {error}")
            raise

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
            # 直接使用类常量
            with open(self.KEY_FILE, 'r') as key_file:
                key = key_file.read().strip()
            
            # 加密新令牌
            from cryptography.fernet import Fernet
            fernet = Fernet(key.encode())
            encrypted_token = fernet.encrypt(new_token.encode()).decode()
            
            # 保存加密后的令牌
            with open(self.TOKEN_FILE, 'w') as token_file:
                token_file.write(encrypted_token)
            
            self.logger.info("令牌已更新并加密保存")
            return True
            
        except Exception as error:
            self.logger.error(f"更新令牌失败: {error}")
            return False

    def set_value(self, section, option, value=None):
        """设置配置项的值
        
        Args:
            section: 配置段名称或配置数据字典
            option: 配置项名称，当section为字典时忽略此参数
            value: 配置值，当section为字典时忽略此参数
            
        Returns:
            bool: 更新成功返回True，失败返回False
        """
        try:
            if not self._config:
                return False
            
            config_data = {}
            if isinstance(section, dict):
                # 批量更新模式
                config_data = section
            else:
                # 单值更新模式
                config_data = {section: {option: value}}
            
            # 更新配置
            for sec, options in config_data.items():
                if not self._config.has_section(sec) and sec != 'GENERAL':
                    self._config.add_section(sec)
                for opt, val in options.items():
                    self._config.set(sec, opt, str(val))
            
            # 保存到文件
            os.makedirs(os.path.dirname(self.CONFIG_FILE), exist_ok=True)
            with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                self._config.write(f)
            
            self.logger.info("配置已更新")
            return True
            
        except Exception as error:
            self.logger.error(f"更新配置失败: {error}")
            return False
