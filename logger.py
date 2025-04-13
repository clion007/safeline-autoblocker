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
    
    def __init__(self):
        """初始化方法 - 加载日志配置"""
        if hasattr(self, '_initialized'):
            return
            
        self._logger = None
        self._config = {}

        # 加载日志配置
        try:
            with open(self.LOG_CONFIG_FILE, 'r', encoding='utf-8') as f:
                self._config = yaml.safe_load(f)
            
            # 配置日志系统
            logging.config.dictConfig(self._config)
        except Exception as e:
            # 初始化时可能还没有日志记录器，使用默认配置
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
