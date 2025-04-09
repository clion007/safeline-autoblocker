#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
日志管理模块
"""

import os
import logging
import glob
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

from config import ConfigManager

class LoggerManager:
    def __init__(self, log_dir=None, log_level=None, use_rotating_handler=True, log_format=None):
        """初始化日志管理器"""
        config_manager = ConfigManager()
        self.log_dir = log_dir or config_manager.get_path('log_dir')
        self.log_file = os.path.join(self.log_dir, os.path.basename(config_manager.get_path('log_file')))
        self.log_level = log_level or DEFAULT_LOG_LEVEL
        self.log_format = log_format or DEFAULT_LOG_FORMAT
        self.use_rotating_handler = use_rotating_handler
        self.logger = self._setup_logger()
    
    def _setup_logger(self):
        """设置日志记录器"""
        # 确保日志目录存在
        os.makedirs(self.log_dir, exist_ok=True)
        
        try:
            logger = logging.getLogger('autoblocker')
            logger.setLevel(self.log_level)
            
            # 清除现有处理器避免重复
            logger.handlers.clear()
            
            # 控制台处理器
            console_handler = logging.StreamHandler()
            console_handler.setLevel(self.log_level)
            
            # 文件处理器
            if self.use_rotating_handler:
                file_handler = RotatingFileHandler(
                    self.log_file,  # 使用实例变量而不是全局常量
                    maxBytes=MAX_LOG_SIZE,
                    backupCount=BACKUP_COUNT,
                    encoding='utf-8'
                )
            else:
                file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
            
            file_handler.setLevel(self.log_level)
            
            # 创建格式化器
            formatter = logging.Formatter(self.log_format)
            
            # 设置处理器
            console_handler.setFormatter(formatter)
            file_handler.setFormatter(formatter)
            
            # 添加处理器
            logger.addHandler(console_handler)
            logger.addHandler(file_handler)
            
            return logger
            
        except Exception as error:
            print(f"设置日志记录时出错: {str(error)}")
            logging.basicConfig(level=self.log_level, format=self.log_format)
            return logging.getLogger('autoblocker')
    
    def get_logger(self):
        """获取日志记录器"""
        return self.logger
    
    def get_log_dir(self):
        """获取日志目录"""
        return self.log_dir
    
    def clean_old_logs(self, retention_days, log_directory=None):
        """清理旧日志文件"""
        try:
            log_dir = log_directory or self.log_dir
            
            # 计算截止日期
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            # 查找所有日志文件
            log_pattern = os.path.join(log_dir, "safeline-autoblocker-*.log*")
            log_files = glob.glob(log_pattern)
            
            # 统计删除的文件数量
            deleted_count = 0
            
            for log_file in log_files:
                # 获取文件修改时间
                file_time = datetime.fromtimestamp(os.path.getmtime(log_file))
                
                # 如果文件早于截止日期，则删除
                if file_time < cutoff_date:
                    os.remove(log_file)
                    deleted_count += 1
            
            if deleted_count > 0:
                self.logger.info(f"已清理 {deleted_count} 个过期日志文件")
        except Exception as error:
            self.logger.error(f"清理旧日志文件时出错: {str(error)}")
# 全局变量用于存储单例实例
_logger_manager_instance = None

def get_logger_manager():
    """获取日志管理器实例（惰性初始化）"""
    global _logger_manager_instance
    if _logger_manager_instance is None:
        _logger_manager_instance = LoggerManager()
    return _logger_manager_instance

def clean_old_logs(retention_days, log_directory=None):
    """清理旧日志文件（兼容旧代码）"""
    get_logger_manager().clean_old_logs(retention_days, log_directory)
