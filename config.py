#!/usr/bin/env python3

"""
配置管理模块
"""

import os
import configparser
import logging

class ConfigManager:
    """配置管理类"""
    
    # 定义路径常量
    CONFIG_DIR = "/etc/safeline"
    KEY_FILE = f"{CONFIG_DIR}/token.key"
    TOKEN_FILE = f"{CONFIG_DIR}/token.enc"
    CONFIG_FILE = f"{CONFIG_DIR}/setting.conf"
    
    def __init__(self, logger=None):
        """初始化配置管理器"""
        if hasattr(self, '_initialized'):
            return
     
        self._logger = logger
        
        # 加载配置
        self._config = None
        self.load()
        
        # 配置加载后，如果没有logger，尝试从工厂获取
        if self._logger is None:
            try:
                from factory import Factory
                self._logger = Factory.get_logger()
            except (ImportError, AttributeError):
                # 如果无法获取工厂日志，则不记录日志
                pass
                
        self._initialized = True
    
    # 删除 _create_default_logger 方法
    
    def log(self, level, message):
        """记录日志"""
        if self._logger:
            getattr(self._logger, level.lower())(message)
    
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
    
    # 移除重复的单例代码
    
    def is_loaded(self):
        """检查配置是否已加载"""
        return self._config is not None
    
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

    def reload(self):
        """重新加载配置"""
        return self.load()
    
    def reset(self):
        """重置配置为默认值"""
        # 实现重置逻辑
        try:
            if os.path.exists(self.CONFIG_FILE):
                os.remove(self.CONFIG_FILE)
            return self.create_default_config()
        except Exception as error:
            self.log('error', f"重置配置失败: {error}")
            return False
