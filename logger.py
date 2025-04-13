#!/usr/bin/env python3

"""
日志管理模块
"""

import os
import glob
import yaml
import logging
import logging.config
from datetime import datetime, timedelta

class LoggerManager:
    # 定义日志配置文件路径常量
    CONFIG_DIR = "/etc/safeline"
    LOG_CONFIG_FILE = f"{CONFIG_DIR}/log.yaml"
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    def __init__(self):
        """初始化方法 - 加载日志配置"""
        if hasattr(self, '_initialized'):
            return
            
        self._logger = None
        self._config = {}

        # 加载日志配置
        try:
            with open(self.LOG_CONFIG_FILE, 'r', encoding='utf-8') as f:
                self._config = yaml.safe_load(f).copy()
        except Exception as e:
            print(f"加载日志配置失败: {e}，使用默认配置")
            self._config = {
                'log_dir': 'logs',
                'log_file': 'error.log',
                'log_level': 'INFO',
                'max_size': 10485760,
                'backup_count': 5,
                'log_format': "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                'retention_days': 30
            }
            
        # 确保日志目录存在（使用绝对路径）
        log_dir = os.path.join(self.BASE_DIR, self._config['log_dir'])
        os.makedirs(log_dir, exist_ok=True)
            
        # 配置日志系统（使用绝对路径）
        log_file = os.path.join(self.BASE_DIR, self._config['log_dir'], self._config['log_file'])
        
        # 创建独立的日志记录器
        self._logger = logging.getLogger('autoblocker')
        self._logger.setLevel(getattr(logging, self._config['log_level']))

        # 创建格式化器
        log_formatter = logging.Formatter(self._config['log_format'])
        
        # 创建处理器
        handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            formatter=log_formatter,
            maxBytes=self._config['max_size'],
            backupCount=self._config['backup_count'],
            encoding='utf-8'
        )
        
        # 添加处理器到日志记录器
        self._logger.addHandler(handler)

        self._initialized = True
    
    def get_config(self, key):
        """获取日志配置项
        
        Args:
            key: 配置项名称
            default: 默认值
            
        Returns:
            配置项的值
        """
        return self._config.get(key, default)
    
    def get_logger(self):
        """获取日志记录器，如果不存在则创建"""
        if self._logger is None:
            self._logger = logging.getLogger('autoblocker')
        return self._logger
    
    def clean_old_logs(self):
        """清理旧日志文件
        
        Args:
            retention_days: 日志保留天数
        """
        log_dir = self.get_config('log_dir')
        log_file = self.get_config('log_file')
        retention_days = self.get_config('retention_days')
        if retention_days is not None:
            retention_days = int(retention_days)
        
        if not log_dir or not log_file:
            return
            
        try:
            # 计算截止日期
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            # 查找所有日志文件
            log_pattern = os.path.join(log_dir, f"{os.path.splitext(log_file)[0]}*.*")
            log_files = glob.glob(log_pattern)
            
            # 删除过期日志
            for log_file in log_files:
                if datetime.fromtimestamp(os.path.getmtime(log_file)) < cutoff_date:
                    os.remove(log_file)
                
        except Exception as error:
            logger = self.get_logger()
            logger.error(f"清理日志文件失败: {error}")
