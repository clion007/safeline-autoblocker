#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
服务工厂模块 - 用于创建和管理服务实例，解决循环依赖问题
"""

class Factory:
    """服务工厂，用于创建和管理服务实例"""
    
    _configer = None
    _logger_manager = None
    _api_client = None
    
    @classmethod
    def get_configer(cls):
        """获取配置管理器实例"""
        if cls._configer is None:
            from configer import ConfigManager
            cls._configer = ConfigManager()
        return cls._configer
    
    @classmethod
    def get_logger_manager(cls):
        """获取日志管理器实例"""
        if cls._logger_manager is None:
            from logger import LoggerManager
            cls._logger_manager = LoggerManager()
        return cls._logger_manager
    
    @classmethod
    def get_logger(cls):
        """获取日志记录器"""
        return cls._logger_manager.get_logger()
    
    @classmethod
    def get_api_client(cls):
        """获取API客户端实例"""
        if cls._api_client is None:
            from api import SafeLineAPI
            cls._api_client = SafeLineAPI(cls.get_configer(), cls.get_logger())
        return cls._api_client