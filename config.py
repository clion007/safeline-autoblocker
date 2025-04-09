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
    
    def __init__(self, logger_instance=None):
        """初始化配置管理器"""
        self.logger = logger_instance or get_logger_manager().get_logger()
        self._config = None
        self._config_values = None
        # 初始化时自动加载配置
        self.load()
    
    def _validate_and_repair_config(self, config):
        """验证配置完整性并修复"""
        is_modified = False
        
        # 检查并补充缺失的配置段
        required_sections = {'TYPE_GROUP_MAPPING'}
        for section in required_sections:
            if section not in config.sections():
                config.add_section(section)
                is_modified = True
        
        # 检查并补充默认配置项
        default_values = {
            'SAFELINE_HOST': 'localhost',
            'SAFELINE_PORT': '9443',
            'HIGH_RISK_IP_GROUP': '黑名单',
            'LOW_RISK_IP_GROUP': '人机验证',
            'QUERY_INTERVAL': '60',
            'MAX_LOGS_PER_QUERY': '100',
            'LOG_RETENTION_DAYS': '30',
            'ATTACK_TYPES_FILTER': ''
        }
        for option, value in default_values.items():
            if option not in config.defaults():
                config.set('DEFAULT', option, str(value))
                is_modified = True
        
        # 检查并补充类型映射配置
        default_mappings = {
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
        for type_id, group in default_mappings.items():
            if not config.has_option('TYPE_GROUP_MAPPING', type_id):
                config.set('TYPE_GROUP_MAPPING', type_id, group)
                is_modified = True
        
        # 如果配置有修改，保存更新
        if is_modified:
            self.logger.warning("配置文件不完整，已自动补充缺失配置")
            with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                config.write(f)
        
        return True
    
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
            self._config_values = self._get_all_values()
            return True
            
        except Exception as error:
            self.logger.error(f"读取配置文件时出错: {str(error)}")
            self.logger.warning("尝试重新创建默认配置")
            if not self.create_default_config():
                return False
            return self.load()
    
    def get_config(self, key, default=None):
        """获取配置值
        
        Args:
            key: 配置键名
            default: 默认值
            
        Returns:
            配置值
        """
        if not self._config_values:
            return default
        return self._config_values.get(key, default)
    
    def get_type_mapping(self, attack_type):
        """获取攻击类型映射
        
        Args:
            attack_type: 攻击类型ID
            
        Returns:
            str: 对应的IP组名称
        """
        if not self._config_values or 'type_group_mapping' not in self._config_values:
            return None
        return self._config_values['type_group_mapping'].get(str(attack_type))
    
    def _get_all_values(self):
        """获取所有配置值"""
        if not self.config:
            return None
            
        values = {}
        
        # 获取默认配置项
        for option in CONFIG_SCHEMA['DEFAULT']:
            try:
                # 获取配置项的验证规则
                schema = CONFIG_SCHEMA['DEFAULT'].get(option, {'type': str, 'default': None})
                value = self.config.defaults().get(option)
                
                # 处理默认值和类型转换
                if value is None:
                    if schema.get('required', False):
                        self.logger.warning(f"必需的配置项 DEFAULT.{option} 不存在，使用默认值: {schema['default']}")
                    values[option] = schema.get('default')
                else:
                    try:
                        values[option] = schema['type'](value)
                    except (ValueError, TypeError) as error:
                        self.logger.error(f"配置项 DEFAULT.{option} 的值 {value} 类型转换失败: {error}")
                        values[option] = schema.get('default')
                        
            except Exception as error:
                self.logger.error(f"获取配置项 DEFAULT.{option} 时出错: {error}")
                values[option] = None
        
        # 获取类型映射配置
        values['type_group_mapping'] = {}
        if self.config.has_section('TYPE_GROUP_MAPPING'):
            for option in self.config.options('TYPE_GROUP_MAPPING'):
                values['type_group_mapping'][option] = self.config.get('TYPE_GROUP_MAPPING', option)
        
        return values
    
    def get_value(self, section, option):
        """获取配置项的值"""
        if not self.config:
            return None
            
        try:
            # 获取配置项的验证规则
            schema = CONFIG_SCHEMA.get(section, {}).get(option)
            if not schema:
                schema = CONFIG_SCHEMA['DEFAULT'].get(option, {'type': str, 'default': None})
            
            # 获取配置值
            if section == 'DEFAULT':
                value = self.config.defaults().get(option)
            else:
                value = self.config.get(section, option, fallback=None)
            
            # 处理默认值和类型转换
            if value is None:
                if schema.get('required', False):
                    self.logger.warning(f"必需的配置项 {section}.{option} 不存在，使用默认值: {schema['default']}")
                return schema.get('default')
            
            try:
                return schema['type'](value)
            except (ValueError, TypeError) as error:
                self.logger.error(f"配置项 {section}.{option} 的值 {value} 类型转换失败: {error}")
                return schema.get('default')
                
        except Exception as error:
            self.logger.error(f"获取配置项 {section}.{option} 时出错: {error}")
            return None
    
    def create_default_config(self):
        """创建默认配置文件"""
        if os.path.exists(self.CONFIG_FILE):
            self.logger.warning(f"配置文件已存在: {self.CONFIG_FILE}")
            return False
        
        default_config = {
            'DEFAULT': {
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
        
        return self.update_config(default_config)
    
    def update_config(self, config_data):
        """更新配置文件"""
        try:
            config = configparser.ConfigParser()
            
            if os.path.exists(self.CONFIG_FILE):
                config.read(self.CONFIG_FILE)
            
            # 更新配置
            for section, options in config_data.items():
                if not config.has_section(section) and section != 'DEFAULT':
                    config.add_section(section)
                for option, value in options.items():
                    config.set(section, option, str(value))
            
            # 确保配置目录存在
            os.makedirs(os.path.dirname(self.CONFIG_FILE), exist_ok=True)
            
            with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                config.write(f)
            
            self.logger.info(f"配置文件已更新: {CONFIG_FILE}")
            # 重新加载配置
            return self.load_config()
            
        except Exception as error:
            self.logger.error(f"更新配置文件失败: {str(error)}")
            return False

    @classmethod
    def get_token(cls, config_values, logger_instance=None):
        """获取解密后的令牌
        
        Args:
            config_values: 配置值字典
            logger_instance: 可选的日志记录器实例
            
        Returns:
            str: 解密后的令牌
        """
        logger_to_use = logger_instance or get_logger_manager().get_logger()
        
        try:
            # 从令牌文件读取加密的令牌
            token_file_path = cls.get_path('token_file')
            if not os.path.exists(token_file_path):
                logger_to_use.error(f"令牌文件不存在: {token_file_path}")
                return None
                
            with open(token_file_path, 'r') as token_file:
                encrypted_token = token_file.read().strip()
            
            # 从密钥文件读取密钥
            key_file_path = cls.get_path('key_file')
            if not os.path.exists(key_file_path):
                logger_to_use.error(f"密钥文件不存在: {key_file_path}")
                return None
                
            with open(key_file_path, 'r') as key_file:
                key = key_file.read().strip()
            
            # 解密令牌
            from cryptography.fernet import Fernet
            fernet = Fernet(key.encode())
            return fernet.decrypt(encrypted_token.encode()).decode()
            
        except Exception as error:
            logger_to_use.error(f"解密令牌失败: {error}")
            return None

    @classmethod
    def update_token(cls, new_token, logger_instance=None):
        """更新并加密保存令牌
        
        Args:
            new_token: 新的令牌字符串
            logger_instance: 可选的日志记录器实例
            
        Returns:
            bool: 更新成功返回True，失败返回False
        """
        logger_to_use = logger_instance or get_logger_manager().get_logger()
        
        try:
            # 读取密钥
            key_file_path = cls.get_path('key_file')
            with open(key_file_path, 'r') as key_file:
                key = key_file.read().strip()
            
            # 加密新令牌
            from cryptography.fernet import Fernet
            fernet = Fernet(key.encode())
            encrypted_token = fernet.encrypt(new_token.encode()).decode()
            
            # 保存加密后的令牌
            token_file_path = cls.get_path('token_file')
            with open(token_file_path, 'w') as token_file:
                token_file.write(encrypted_token)
            
            logger_to_use.info("令牌已更新并加密保存")
            return True
            
        except Exception as error:
            logger_to_use.error(f"更新令牌失败: {error}")
            return False
