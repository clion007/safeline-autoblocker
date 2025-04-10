#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
服务工厂模块 - 用于创建和管理服务实例，解决循环依赖问题
"""

class Factory:
    """服务工厂，用于创建和管理服务实例"""
    
    _config_manager = None
    _logger_manager = None
    _api_client = None
    
    @classmethod
    def get_config_manager(cls):
        """获取配置管理器实例"""
        if cls._config_manager is None:
            from config import ConfigManager
            # 初始化时不传入logger，避免循环依赖
            cls._config_manager = ConfigManager(logger=None)
            cls._config_manager.load()
        return cls._config_manager
    
    @classmethod
    def get_logger_manager(cls):
        """获取日志管理器实例"""
        if cls._logger_manager is None:
            from logger import LoggerManager
            config = cls.get_config_manager()
            cls._logger_manager = LoggerManager(config)
        return cls._logger_manager
    
    @classmethod
    def get_logger(cls):
        """获取日志记录器实例"""
        return cls.get_logger_manager().get_logger()
    
    @classmethod
    def get_api_client(cls):
        """获取API客户端实例"""
        if cls._api_client is None:
            from api import SafeLineAPI
            config = cls.get_config_manager()
            logger = cls.get_logger_manager().get_logger()
            cls._api_client = SafeLineAPI(config, logger)
        return cls._api_client
    
    @classmethod
    def reset(cls):
        """重置所有服务实例"""
        cls._config_manager = None
        cls._logger_manager = None
        cls._api_client = None