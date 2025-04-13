#!/usr/bin/env python3

"""
配置管理模块
"""

import os
import configparser

class ConfigManager:
    """配置管理类"""
    
    # 定义路径常量
    CONFIG_DIR = "/etc/safeline"
    KEY_FILE = f"{CONFIG_DIR}/token.key"
    TOKEN_FILE = f"{CONFIG_DIR}/token.enc"
    CONFIG_FILE = f"{CONFIG_DIR}/setting.conf"
    LOG_CONFIG_FILE = f"{CONFIG_DIR}/log.yaml"
    
    # 定义默认配置
    DEFAULT_CONFIG = {
        'GENERAL': {
            'SAFELINE_HOST': 'localhost',
            'SAFELINE_PORT': '9443',
            'API_PREFIX': '/api/open',
            'HIGH_RISK_IP_GROUP': '黑名单',
            'LOW_RISK_IP_GROUP': '人机验证',
            'QUERY_INTERVAL': '60',
            'MAX_LOGS_PER_QUERY': '100',
            'ATTACK_TYPES_FILTER': '-3',     # 默认过滤黑名单类型
        },
        'MAINTENANCE': {
            'CACHE_CLEAN_INTERVAL': '3600'
        },
        'TYPE_GROUP': {
            'HIGH_RISK_TYPES': '0,5,7,8,9,11,29',  # SQL注入,后门,代码执行,代码注入,命令注入,文件包含,模板注入
            'LOW_RISK_TYPES': '1,2,3,4,6,10,21'    # XSS,CSRF,SSRF,拒绝服务,反序列化,文件上传,扫描器
        }
    }
    
    def __init__(self):
        """初始化配置管理器"""
        if hasattr(self, '_initialized'):
            return
     
        self._logger = None
        self._config = None
        self._initialized = True
    
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
            return self
            
        except Exception as error:
            logger = self.get_logger()
            logger.error(f"读取配置文件时出错: {str(error)}")
            return False
    
    def get_logger(self):
        """获取日志记录器"""
        if self._logger is None:
            from factory import Factory
            self._logger = Factory.get_logger()
        return self._logger

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
            
            if option in {'SAFELINE_PORT', 'QUERY_INTERVAL', 'MAX_LOGS_PER_QUERY'}:
                return int(value)
            return value
                
        except Exception as error:
            logger = self.get_logger()
            logger.error(f"获取配置项 {section}.{option} 时出错: {error}")
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
            logger = self.get_logger()
            logger.error(f"更新配置失败: {error}")
            return False

    def get_token(self):
        """获取API令牌"""
        try:
            # 读取密钥
            with open(self.KEY_FILE, 'r') as f:
                key = f.read().strip()
            
            # 读取加密的令牌
            with open(self.TOKEN_FILE, 'r') as f:
                encrypted_token = f.read().strip()
            
            # 解密令牌（与安装脚本保持一致）
            from cryptography.fernet import Fernet
            f = Fernet(key.encode())
            token = f.decrypt(encrypted_token.encode()).decode()
            return token
        except Exception as e:
            self.get_logger().error(f"获取API令牌失败: {str(e)}")
            return None

    def update_token(self, new_token):
        """更新API令牌"""
        try:
            # 读取密钥
            with open(self.KEY_FILE, 'r') as f:
                key = f.read().strip()
            
            # 加密新令牌（与安装脚本保持一致）
            from cryptography.fernet import Fernet
            f = Fernet(key.encode())
            encrypted_token = f.encrypt(new_token.encode()).decode()
            
            # 保存加密的令牌
            with open(self.TOKEN_FILE, 'w') as f:
                f.write(encrypted_token)
            
            return True
        except Exception as e:
            self.get_logger().error(f"更新API令牌失败: {str(e)}")
            return False

    def reload(self):
        """重新加载配置"""
        if self._config is not None:
            self._config.clear()
        success = self.load()
        
        if success:
            from factory import Factory
            Factory.get_logger_manager().reload()
            logger = self.get_logger()
            logger.info('配置已成功重新加载')
            logger.info('日志配置重新加载成功')
        
        return success
    
    def reset(self):
        """重置配置为默认值"""
        try:
            if os.path.exists(self.CONFIG_FILE):
                os.remove(self.CONFIG_FILE)
            return self.create_default_config()
        except Exception as error:
            logger = self.get_logger()
            logger.error('error', f"重置配置失败: {error}")
            return False
    
    def set_log_config(self, key, value):
        """设置日志配置项
        
        Args:
            key: 配置项名称 (log_level, log_dir, log_file, max_size, backup_count, retention_days, log_format)
            value: 配置值
        """
        try:
            import yaml
            
            # 读取现有配置
            if os.path.exists(self.LOG_CONFIG_FILE):
                with open(self.LOG_CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f) or {}
            else:
                config = {}
            
            # 更新配置项
            config[key] = value
            
            # 写入配置
            os.makedirs(os.path.dirname(self.LOG_CONFIG_FILE), exist_ok=True)
            with open(self.LOG_CONFIG_FILE, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, allow_unicode=True)
            
            # 重新加载日志系统
            from factory import Factory
            Factory.get_logger_manager().reload()
            
            return True
            
        except Exception as error:
            logger = self.get_logger()
            logger.error(f"更新日志配置失败: {error}")
            return False

    def get_risk_level_for_attack_type(self, attack_type_id):
        """获取攻击类型的风险等级"""
        high_risk_types = set(self.get_value('TYPE_GROUP', 'HIGH_RISK_TYPES').split(','))
        low_risk_types = set(self.get_value('TYPE_GROUP', 'LOW_RISK_TYPES').split(','))
        
        attack_type_str = str(attack_type_id)
        if attack_type_str in high_risk_types:
            return 'HIGH'
        elif attack_type_str in low_risk_types:
            return 'LOW'
        return 'LOW'  # 默认为低危
    
    def get_ip_group_for_attack_type(self, attack_type_id):
        """根据攻击类型获取对应的IP组名称"""
        try:
            risk_level = self.get_risk_level_for_attack_type(attack_type_id)
            if risk_level == 'HIGH':
                return self.get_value('GENERAL', 'HIGH_RISK_IP_GROUP')
            return self.get_value('GENERAL', 'LOW_RISK_IP_GROUP')
        except Exception as error:
            logger = self.get_logger()
            logger.error(f"获取攻击类型 {attack_type_id} 对应的IP组失败: {error}")
            return self.get_value('GENERAL', 'LOW_RISK_IP_GROUP')  # 默认返回低危IP组
