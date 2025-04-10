#!/usr/bin/env python3

"""
日志管理模块
"""

import os
import glob
import logging
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

class LoggerManager:
    # 移除单例相关代码，由工厂类负责单例管理
    
    def __init__(self, config_manager=None):
        """初始化方法"""
        if hasattr(self, '_initialized'):
            return
            
        self._logger = None
        self._config_manager = config_manager
        
        try:
            # 如果没有传入配置管理器，尝试使用工厂获取
            if self._config_manager is None:
                from factory import Factory
                self._config_manager = Factory.get_config_manager()
            
            # 获取日志配置
            log_level_name = self._config_manager.get_value('LOGS', 'LEVEL', 'INFO')
            # 更健壮的日志级别处理
            log_levels = {
                'DEBUG': logging.DEBUG,
                'INFO': logging.INFO,
                'WARNING': logging.WARNING,
                'ERROR': logging.ERROR,
                'CRITICAL': logging.CRITICAL
            }
            log_level = log_levels.get(log_level_name.upper(), logging.INFO)
            
            log_dir = self._config_manager.get_value('LOGS', 'DIRECTORY', 'logs')
            log_file = self._config_manager.get_value('LOGS', 'FILENAME', 'erro.log')
            
            # 使用默认值避免类型转换异常
            try:
                max_size = int(self._config_manager.get_value('LOGS', 'MAX_SIZE', '10485760'))
            except (ValueError, TypeError):
                max_size = 10 * 1024 * 1024  # 默认10MB
            
            try:
                backup_count = int(config_manager.get_value('LOGS', 'BACKUP_COUNT', '5'))
            except (ValueError, TypeError):
                backup_count = 5
            
            log_format = config_manager.get_value('LOGS', 'FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            
            # 初始化日志记录器
            os.makedirs(log_dir, exist_ok=True)
            
            logger = logging.getLogger('autoblocker')
            logger.setLevel(log_level)
            logger.handlers.clear()
            
            # 控制台处理器
            console_handler = logging.StreamHandler()
            console_handler.setLevel(log_level)
            
            # 文件处理器
            file_path = os.path.join(log_dir, log_file)
            file_handler = RotatingFileHandler(
                file_path,
                maxBytes=max_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(log_level)
            
            # 设置格式化器
            formatter = logging.Formatter(log_format)
            console_handler.setFormatter(formatter)
            file_handler.setFormatter(formatter)
            
            # 添加处理器
            logger.addHandler(console_handler)
            logger.addHandler(file_handler)
            
            self._logger = logger
            self._log_dir = log_dir
            self._log_file = log_file
            
        except Exception as error:
            # 如果初始化失败，创建一个最基本的控制台日志记录器
            # 这是唯一允许的非工厂日志实例，仅用于记录初始化失败
            logger = logging.getLogger('autoblocker_emergency')
            logger.setLevel(logging.ERROR)
            logger.handlers.clear()
            
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.ERROR)
            formatter = logging.Formatter('%(asctime)s - EMERGENCY - %(levelname)s - %(message)s')
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
            
            self._logger = logger
            self._logger.error(f"初始化日志系统时出错: {str(error)}")
        
        self._initialized = True
    
    # 删除 _create_default_logger 方法，或将其改为私有的紧急日志创建方法
    
    def get_logger(self):
        """获取日志记录器"""
        return self._logger
    
    def clean_old_logs(self, retention_days):
        """清理旧日志文件"""
        try:
            # 计算截止日期
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            # 查找所有日志文件
            log_pattern = os.path.join(self._log_dir, f"{os.path.splitext(self._log_file)[0]}*.*")
            log_files = glob.glob(log_pattern)
            
            # 删除过期日志
            deleted_count = 0
            for log_file in log_files:
                if datetime.fromtimestamp(os.path.getmtime(log_file)) < cutoff_date:
                    os.remove(log_file)
                    deleted_count += 1
            
            if deleted_count > 0:
                self._logger.debug(f"已清理 {deleted_count} 个过期日志文件")
                
        except Exception as error:
            self._logger.error(f"清理日志文件失败: {error}")
