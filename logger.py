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
        """初始化方法 - 不处理任何配置逻辑"""
        if hasattr(self, '_initialized'):
            return
            
        self._logger = None

        # 加载日志配置
        with open(self.LOG_CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    
        self._log_dir = config.get('log_dir', 'logs')
        self._log_file = config.get('log_file', 'app.log')
        logging.config.dictConfig(config)
            
        self._initialized = True
    
    def get_logger(self):
        """获取日志记录器，如果不存在则创建"""
        if self._logger is None:
            self._logger = logging.getLogger('autoblocker')
        return self._logger
    
    def clean_old_logs(self, retention_days):
        """清理旧日志文件"""
        if not self._log_dir or not self._log_file:
            return
            
        try:
            # 计算截止日期
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            # 查找所有日志文件
            log_pattern = os.path.join(self._log_dir, f"{os.path.splitext(self._log_file)[0]}*.*")
            log_files = glob.glob(log_pattern)
            
            # 删除过期日志
            for log_file in log_files:
                if datetime.fromtimestamp(os.path.getmtime(log_file)) < cutoff_date:
                    os.remove(log_file)
                
        except Exception as error:
            logger = self.get_logger()
            logger.error(f"清理日志文件失败: {error}")
