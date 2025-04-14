#!/usr/bin/env python3

"""
日志管理模块
"""

import os
import glob
import yaml
import logging
import logging.handlers
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
                self._config = yaml.safe_load(f)
        except Exception as e:
            print(f"加载日志配置失败: {e}，使用默认配置")
            self._config = {
                'log_dir': 'logs',
                'log_file': 'error.log',
                'log_level': 'INFO',
                'max_size': 10485760,
                'backup_count': 5,
                'log_format': "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                'retention_days': 30,
                'clean_interval': 86400  # 添加日志清理间隔配置，默认24小时
            }
            
        # 确保日志目录存在（使用绝对路径）
        log_dir = self.get_config('log_dir')
        os.makedirs(log_dir, exist_ok=True)

        self._initialized = True
    
    def get_config(self, key):
        """获取日志配置项"""
        if key == 'log_dir' :
            return os.path.join(self.BASE_DIR, self._config['log_dir'])
        elif key == 'log_file' :
            return os.path.join(self.BASE_DIR, self._config['log_dir'], self._config['log_file'])
        else:
            return self._config.get(key)
    
    def get_logger(self):
        """获取日志记录器，如果不存在则创建"""
        if self._logger is None:
            # 创建独立的日志记录器
            self._logger = logging.getLogger('autoblocker')
            
            # 避免重复添加handlers
            if not self._logger.handlers:
                # 配置日志系统
                log_file = self.get_config('log_file')
                self._logger.setLevel(getattr(logging, self.get_config('log_level').upper()))

                # 创建格式化器和处理器
                log_formatter = logging.Formatter(self.get_config('log_format'))
                handler = logging.handlers.RotatingFileHandler(
                    filename=log_file,
                    maxBytes=self.get_config('max_size'),
                    backupCount=self.get_config('backup_count'),
                    encoding='utf-8'
                )
                handler.setFormatter(log_formatter)
                self._logger.addHandler(handler)
            
        return self._logger

    def clean_old_logs(self):
        """清理旧日志文件"""
        try:
            retention_days = int(self.get_config('retention_days'))
            if retention_days <= 0:
                return
                
            log_dir = self.get_config('log_dir')
            log_file = self.get_config('log_file')
            
            # 计算截止日期
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            # 获取日志文件名（不含路径）用于构建通配符模式
            log_file_name = os.path.basename(log_file)
            
            # 查找所有日志文件
            log_pattern = os.path.join(log_dir, f"{os.path.splitext(log_file_name)[0]}*.*")
            log_files = glob.glob(log_pattern)
            
            # 删除过期日志
            deleted_count = 0
            for log_file in log_files:
                if datetime.fromtimestamp(os.path.getmtime(log_file)) < cutoff_date:
                    os.remove(log_file)
                    deleted_count += 1
            
            if deleted_count > 0:
                self.get_logger().debug(f"已清理 {deleted_count} 个过期日志文件")
                
        except Exception as error:
            self.get_logger().error(f"清理日志文件失败: {error}")

    def reload(self):
        """重新加载日志配置"""
        # 清理现有logger
        if self._logger:
            for handler in self._logger.handlers[:]:
                self._logger.removeHandler(handler)
            self._logger = None
        
        # 重新初始化
        self.__init__()
        
        # 重新获取日志记录器
        return self.get_logger()
