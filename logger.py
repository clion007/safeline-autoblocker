#!/usr/bin/env python3

"""
日志管理模块
"""

import os
import glob
import logging
import threading
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

class LoggerManager:
    # 定义日志相关常量
    BACKUP_COUNT = 5
    LOG_DIR = "logs"
    LOG_LEVEL = logging.ERROR
    LOG_FILE = f"{LOG_DIR}/erro.log"
    MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB
    LOG_PATTERN = f"{LOG_DIR}/erro*.log*"
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls):
        """获取线程安全的单例实例"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:  # 双检锁
                    cls._instance = cls.__new__(cls)
                    cls._instance.__init__()
        return cls._instance
    
    def __init__(self):
        """初始化方法（通过单例控制只执行一次）"""
        if not hasattr(self, '_initialized'):
            self._logger = None
            try:
                # 初始化日志记录器的实际逻辑
                os.makedirs(self.LOG_DIR, exist_ok=True)
                
                logger = logging.getLogger('autoblocker')
                logger.setLevel(self.LOG_LEVEL)
                logger.handlers.clear()
                
                # 控制台处理器
                console_handler = logging.StreamHandler()
                console_handler.setLevel(self.LOG_LEVEL)
                
                # 文件处理器
                file_handler = RotatingFileHandler(
                    self.LOG_FILE,
                    maxBytes=self.MAX_LOG_SIZE,
                    backupCount=self.BACKUP_COUNT,
                    encoding='utf-8'
                )
                file_handler.setLevel(self.LOG_LEVEL)
                
                # 设置格式化器
                formatter = logging.Formatter(self.LOG_FORMAT)
                console_handler.setFormatter(formatter)
                file_handler.setFormatter(formatter)
                
                # 添加处理器
                logger.addHandler(console_handler)
                logger.addHandler(file_handler)
                
                self._logger = logger
                
            except Exception as error:
                logging.error(f"初始化日志记录器失败: {error}")
                logging.basicConfig(level=self.LOG_LEVEL, format=self.LOG_FORMAT)
                self._logger = logging.getLogger('autoblocker')
            
            self._initialized = True
            
    def get_logger(self):
        """获取日志记录器"""
        return self._logger
    
    def clean_old_logs(self, retention_days):
        """清理旧日志文件"""
        try:
            # 计算截止日期
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            # 查找所有日志文件
            log_files = glob.glob(self.LOG_PATTERN)
            
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
