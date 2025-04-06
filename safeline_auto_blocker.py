#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SafeLine Auto Blocker
---------------------
通过API监控雷池WAF安全日志并自动封禁攻击IP的工具。

作者: Clion Nieh
版本: 1.2.0
日期: 2025.4.6
许可证: MIT
"""

import os
import sys
import time
import json
import logging
import argparse
import configparser
import requests
import glob
import re
import shutil
import signal
import threading
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
# 在导入部分添加
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# 配置日志 - 初始配置，后续会被setup_logging替换
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('safeline_auto_blocker')

# 全局变量
CONFIG_FILE = '/etc/safeline/auto_blocker.conf'
KEY_FILE = '/etc/safeline/auto_blocker.key'
VERSION = '1.2.0'  # 修改版本号与文档注释一致

class SafeLineAPI:
    """雷池WAF API接口类"""
    
    def __init__(self, host, port, token, max_retries=3):
        """初始化API接口"""
        self.host = host
        self.port = port
        self.token = token
        self.headers = {
            'X-SLCE-API-TOKEN': self.token,
            'Content-Type': 'application/json'
        }
        
        # 设置重试策略
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "PUT", "POST", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        
        # IP组缓存
        self.ip_groups_cache = {}
        self.ip_groups_cache_time = None
        self.ip_groups_cache_ttl = 300  # 缓存有效期5分钟
        
        # 已添加IP缓存
        self.added_ips_cache = {}
    
    def get_attack_logs(self, limit=100, attack_type=None):
        """获取攻击日志"""
        url = f"https://{self.host}:{self.port}/api/open/records"
        
        # 使用page和page_size参数获取最新的日志
        params = {
            'page': 1,
            'page_size': limit
        }
        
        if attack_type:
            params['attack_type'] = attack_type
        
        try:
            response = self.session.get(url, params=params, headers=self.headers)
            if response.status_code == 200:
                result = response.json()
                data = result.get('data', {}).get('data', [])
                return data
            else:
                logger.error(f"获取攻击日志失败: {response.status_code} - {response.text}")
                return []
        except Exception as e:
            logger.error(f"获取攻击日志异常: {str(e)}")
            return []
    
    def add_ip_to_group(self, ip, reason, group_name):
        """添加IP到指定IP组"""
        # 检查缓存中是否已添加该IP
        cache_key = f"{ip}_{group_name}"
        if cache_key in self.added_ips_cache:
            return True
        
        # 首先获取IP组信息
        group_info = self._get_ip_group_info(group_name)
        if not group_info:
            logger.error(f"未找到IP组: {group_name}")
            return False
        
        group_id = group_info.get('id')
        current_ips = group_info.get('ips', [])
        
        # 检查IP是否已经在组中
        if ip in current_ips:
            # 添加到缓存
            self.added_ips_cache[cache_key] = datetime.now()
            return True
        
        # 添加新IP到列表
        current_ips.append(ip)
        
        url = f"https://{self.host}:{self.port}/api/open/ipgroup"
        
        data = {
            "id": group_id,
            "comment": group_name,
            "reference": "",
            "ips": current_ips
        }
        
        try:
            response = self.session.put(url, headers=self.headers, json=data)
            success = response.status_code == 200 and response.json().get('err') is None
            
            if success:
                # 添加到缓存
                self.added_ips_cache[cache_key] = datetime.now()
                logger.debug(f"成功添加IP {ip} 到 {group_name} 组，原因: {reason}")
            else:
                logger.error(f"添加IP {ip} 到 {group_name} 组失败: {response.text}")
            
            return success
        except Exception as e:
            logger.error(f"添加IP到IP组异常: {str(e)}")
            return False
    
    def _get_ip_group_info(self, group_name):
        """获取IP组信息，使用缓存减少API请求"""
        # 检查缓存是否有效
        current_time = datetime.now()
        if (self.ip_groups_cache_time is not None and 
            (current_time - self.ip_groups_cache_time).total_seconds() < self.ip_groups_cache_ttl and
            group_name in self.ip_groups_cache):
            return self.ip_groups_cache[group_name]
        
        # 缓存无效，重新获取所有IP组
        url = f"https://{self.host}:{self.port}/api/open/ipgroup"
        
        try:
            response = self.session.get(url, headers=self.headers)
            if response.status_code != 200:
                logger.error(f"获取IP组列表失败: {response.status_code} - {response.text}")
                return None
            
            result = response.json()
            if 'data' not in result or 'nodes' not in result['data']:
                logger.error("IP组数据格式不正确")
                return None
            
            # 更新缓存
            self.ip_groups_cache = {}
            self.ip_groups_cache_time = current_time
            
            for group in result['data']['nodes']:
                if group.get('comment') == group_name:
                    # 获取详细信息
                    detail_url = f"https://{self.host}:{self.port}/api/open/ipgroup/detail?id={group.get('id')}"
                    detail_response = self.session.get(detail_url, headers=self.headers)
                    
                    if detail_response.status_code == 200:
                        detail_result = detail_response.json()
                        if 'data' in detail_result and 'data' in detail_result['data']:
                            group_info = detail_result['data']['data']
                            self.ip_groups_cache[group_name] = group_info
                            return group_info
                    
                    self.ip_groups_cache[group_name] = group
                    return group
            
            logger.error(f"未找到名为 {group_name} 的IP组")
            return None
        
        except Exception as e:
            logger.error(f"获取IP组信息异常: {str(e)}")
            return None
    
    def get_attack_types(self):
        """获取攻击类型列表"""
        # 尝试从API获取攻击类型，如果失败则返回硬编码列表
        url = f"https://{self.host}:{self.port}/api/open/attack_types"
        
        try:
            response = self.session.get(url, headers=self.headers)
            if response.status_code == 200:
                result = response.json()
                if 'data' in result:
                    return result['data']
        except Exception as e:
            logger.warning(f"从API获取攻击类型失败，使用硬编码列表: {str(e)}")
        
        # 返回硬编码的攻击类型列表
        attack_types = [
            {"id": 0, "name": "SQL注入"},
            {"id": 1, "name": "XSS"},
            {"id": 2, "name": "CSRF"},
            {"id": 3, "name": "SSRF"},
            {"id": 4, "name": "拒绝服务"},
            {"id": 5, "name": "后门"},
            {"id": 6, "name": "反序列化"},
            {"id": 7, "name": "代码执行"},
            {"id": 8, "name": "代码注入"},
            {"id": 9, "name": "命令注入"},
            {"id": 10, "name": "文件上传"},
            {"id": 11, "name": "文件包含"},
            {"id": 21, "name": "扫描器"},
            {"id": 29, "name": "模板注入"}
        ]
        return attack_types
    
    def clean_cache(self):
        """清理过期的IP缓存"""
        current_time = datetime.now()
        expired_keys = []
        
        # 查找过期的缓存项
        for key, timestamp in self.added_ips_cache.items():
            if (current_time - timestamp).total_seconds() > 3600:  # 1小时过期
                expired_keys.append(key)
        
        # 删除过期项
        for key in expired_keys:
            del self.added_ips_cache[key]
        
        if expired_keys:
            logger.debug(f"已清理 {len(expired_keys)} 个过期IP缓存项")

def encrypt_token(token, key):
    """加密API令牌"""
    f = Fernet(key.encode())
    return f.encrypt(token.encode()).decode()

def decrypt_token(encrypted_token, key):
    """解密API令牌"""
    f = Fernet(key.encode())
    return f.decrypt(encrypted_token.encode()).decode()

def parse_config(config_file=CONFIG_FILE):
    """解析配置文件"""
    config = configparser.ConfigParser()
    
    if not os.path.exists(config_file):
        logger.error(f"配置文件不存在: {config_file}")
        return None
    
    try:
        config.read(config_file)
        return config
    except Exception as e:
        logger.error(f"解析配置文件时出错: {str(e)}")
        return None

def process_log_entry(log_entry, api, default_ip_group, use_type_groups, type_group_mapping, attack_types_filter):
    """处理单个日志条目"""
    # 根据实际API返回的字段名获取IP和攻击类型
    ip = log_entry.get('src_ip')  # 使用src_ip而不是client_ip
    attack_type = log_entry.get('attack_type')
    url = log_entry.get('website', '')  # 使用website而不是url
    
    if not ip or attack_type is None:
        return False
    
    # 排除黑名单攻击类型(ID为-3)
    if attack_type == -3:
        return False
    
    # 如果设置了攻击类型过滤，检查是否在过滤列表中
    if attack_types_filter and str(attack_type) not in attack_types_filter:
        # 对于不在过滤列表中的攻击类型，将其IP添加到人机验证组
        attack_type_name = get_attack_type_name(attack_type)
        reason = f"未列举攻击类型: {attack_type_name} - {url}"
        return api.add_ip_to_group(ip, reason, default_ip_group)
    
    # 获取攻击类型名称
    attack_type_name = get_attack_type_name(attack_type)
    
    # 确定IP组
    ip_group = default_ip_group
    if use_type_groups and str(attack_type) in type_group_mapping:
        ip_group = type_group_mapping[str(attack_type)]
    
    # 构建原因
    reason = f"{attack_type_name} - {url}"
    
    # 添加IP到IP组
    return api.add_ip_to_group(ip, reason, ip_group)

# 攻击类型名称缓存
attack_type_names = {}

def get_attack_type_name(attack_type_id):
    """获取攻击类型名称，使用缓存提高性能"""
    global attack_type_names
    
    # 如果缓存中有，直接返回
    if attack_type_id in attack_type_names:
        return attack_type_names[attack_type_id]
    
    # 否则使用硬编码映射
    attack_types = {
        0: "SQL注入",
        1: "XSS",
        2: "CSRF",
        3: "SSRF",
        4: "拒绝服务",
        5: "后门",
        6: "反序列化",
        7: "代码执行",
        8: "代码注入",
        9: "命令注入",
        10: "文件上传",
        11: "文件包含",
        21: "扫描器",
        29: "模板注入"
    }
    
    name = attack_types.get(attack_type_id, f"未知类型({attack_type_id})")
    
    # 添加到缓存
    attack_type_names[attack_type_id] = name
    
    return name

def update_attack_type_names(api):
    """从API更新攻击类型名称"""
    global attack_type_names
    
    try:
        attack_types = api.get_attack_types()
        for attack_type in attack_types:
            attack_id = attack_type.get('id')
            attack_name = attack_type.get('name')
            if attack_id is not None and attack_name:
                attack_type_names[attack_id] = attack_name
        
        logger.debug(f"已更新 {len(attack_types)} 个攻击类型名称")
    except Exception as e:
        logger.error(f"更新攻击类型名称时出错: {str(e)}")

def clean_old_logs(log_dir, retention_days):
    """清理过期的日志文件"""
    if retention_days <= 0:
        return
    
    try:
        # 获取当前日期
        current_date = datetime.now()
        # 计算截止日期
        cutoff_date = current_date - timedelta(days=retention_days)
        
        # 日志文件名格式：auto_blocker.log.YYYY-MM-DD
        log_pattern = os.path.join(log_dir, "auto_blocker.log.*")
        log_files = glob.glob(log_pattern)
        
        # 日期提取正则表达式
        date_pattern = re.compile(r'auto_blocker\.log\.(\d{4}-\d{2}-\d{2})')
        
        deleted_count = 0
        for log_file in log_files:
            match = date_pattern.search(log_file)
            if match:
                log_date_str = match.group(1)
                try:
                    log_date = datetime.strptime(log_date_str, "%Y-%m-%d")
                    if log_date < cutoff_date:
                        os.remove(log_file)
                        deleted_count += 1
                except ValueError:
                    logger.warning(f"无法解析日志文件日期: {log_file}")
        
        if deleted_count > 0:
            logger.debug(f"已删除 {deleted_count} 个过期日志文件")
    
    except Exception as e:
        logger.error(f"清理日志文件时出错: {str(e)}")

def check_log_rotation(log_file, max_size=10*1024*1024):
    """检查并执行日志轮转"""
    if os.path.exists(log_file) and os.path.getsize(log_file) > max_size:
        # 生成带日期的备份文件名
        backup_file = f"{log_file}.{datetime.now().strftime('%Y-%m-%d')}"
        
        # 如果同一天已经有备份，添加序号
        counter = 1
        while os.path.exists(backup_file):
            backup_file = f"{log_file}.{datetime.now().strftime('%Y-%m-%d')}.{counter}"
            counter += 1
        
        # 重命名当前日志文件
        try:
            shutil.move(log_file, backup_file)
            logger.debug(f"日志文件已轮转: {log_file} -> {backup_file}")
            return True
        except Exception as e:
            logger.error(f"轮转日志文件失败: {str(e)}")
    
    return False

def setup_logging():
    """设置日志记录"""
    log_dir = '/var/log/safeline'
    log_file = os.path.join(log_dir, 'auto_blocker.log')
    
    # 确保日志目录存在
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except Exception as e:
            print(f"创建日志目录失败: {str(e)}")
            sys.exit(1)
    
    # 检查日志轮转
    check_log_rotation(log_file)
    
    # 创建日志处理器
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)  # 文件日志记录DEBUG级别
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)  # 控制台也显示DEBUG级别
    
    # 配置日志格式
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # 配置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # 根日志级别设置为DEBUG
    root_logger.handlers = []  # 清除现有处理器
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # 获取应用日志记录器
    app_logger = logging.getLogger('safeline_auto_blocker')
    
    return app_logger, log_dir

# 在main函数之前添加daemonize函数
def daemonize():
    """将程序转为守护进程运行（仅支持Unix/Linux）"""
    try:
        # 第一次fork
        pid = os.fork()
        if pid > 0:
            # 父进程退出
            sys.exit(0)
    except OSError as e:
        logger.error(f"第一次fork失败: {e}")
        sys.exit(1)
    
    # 修改工作目录
    os.chdir('/')
    # 设置新会话
    os.setsid()
    # 修改文件创建掩码
    os.umask(0)
    
    try:
        # 第二次fork
        pid = os.fork()
        if pid > 0:
            # 第二个父进程退出
            sys.exit(0)
    except OSError as e:
        logger.error(f"第二次fork失败: {e}")
        sys.exit(1)
    
    # 重定向标准文件描述符
    sys.stdout.flush()
    sys.stderr.flush()
    
    with open('/dev/null', 'r') as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open('/dev/null', 'a+') as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
    with open('/dev/null', 'a+') as f:
        os.dup2(f.fileno(), sys.stderr.fileno())
    
    logger.info(f"守护进程已启动，PID: {os.getpid()}")

def reload_config(config_file=CONFIG_FILE):
    """重新加载配置文件"""
    try:
        new_config = parse_config(config_file)
        if new_config:
            logger.debug("配置文件已重新加载")
            return new_config
    except Exception as e:
        logger.error(f"重新加载配置文件时出错: {str(e)}")
    
    return None

def api_monitor(config):
    """API监控模式"""
    # 获取配置
    host = config.get('DEFAULT', 'SAFELINE_HOST', fallback='localhost')
    port = config.get('DEFAULT', 'SAFELINE_PORT', fallback='9443')
    encrypted_token = config.get('DEFAULT', 'SAFELINE_TOKEN_ENCRYPTED')
    default_ip_group = config.get('DEFAULT', 'DEFAULT_IP_GROUP', fallback='人机验证')
    use_type_groups = config.getboolean('DEFAULT', 'USE_TYPE_GROUPS', fallback=True)
    query_interval = config.getint('DEFAULT', 'QUERY_INTERVAL', fallback=60)
    max_logs = config.getint('DEFAULT', 'MAX_LOGS_PER_QUERY', fallback=100)
    debug_mode = config.getboolean('DEFAULT', 'DEBUG_MODE', fallback=False)
    log_retention_days = config.getint('DEFAULT', 'LOG_RETENTION_DAYS', fallback=30)
    attack_types_filter = config.get('DEFAULT', 'ATTACK_TYPES_FILTER', fallback='').split(',')
    attack_types_filter = [t.strip() for t in attack_types_filter if t.strip()]
    config_reload_interval = config.getint('DEFAULT', 'CONFIG_RELOAD_INTERVAL', fallback=300)
    
    # 设置日志级别
    if debug_mode:
        logger.setLevel(logging.DEBUG)
    
    # 读取密钥
    try:
        with open(KEY_FILE, 'r') as f:
            key = f.read().strip()
    except Exception as e:
        logger.error(f"读取密钥文件时出错: {str(e)}")
        return
    
    # 解密令牌
    try:
        token = decrypt_token(encrypted_token, key)
    except Exception as e:
        logger.error(f"解密令牌时出错: {str(e)}")
        return
    
    # 创建API实例
    api = SafeLineAPI(host, port, token)
    
    # 获取类型组映射
    type_group_mapping = {}
    if 'TYPE_GROUP_MAPPING' in config:
        type_group_mapping = dict(config['TYPE_GROUP_MAPPING'])
    
    # 创建一个集合来记录已处理过的日志ID
    processed_log_ids = set()
    # 设置集合最大大小，避免内存占用过大
    max_processed_ids = 10000
    
    # 记录上次日志清理时间
    last_log_cleanup = datetime.now()
    # 记录上次配置重载时间
    last_config_reload = datetime.now()
    # 记录上次日志轮转检查时间
    last_log_rotation_check = datetime.now()
    # 记录上次攻击类型更新时间
    last_attack_types_update = datetime.now()
    # 记录上次缓存清理时间
    last_cache_cleanup = datetime.now()
    
    # 添加信号处理
    running = True
    
    def signal_handler(sig, frame):
        nonlocal running
        logger.info(f"收到信号 {sig}，准备退出...")
        running = False
    
    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.debug("启动API监控模式，已注册信号处理器")
    
    # 主循环
    while running:
        try:
            # 记录循环开始时间
            loop_start_time = time.time()
            
            # 检查是否需要重新加载配置
            current_time = datetime.now()
            if (current_time - last_config_reload).total_seconds() >= config_reload_interval:
                new_config = reload_config()
                if new_config:
                    config = new_config
                    # 更新配置项
                    default_ip_group = config.get('DEFAULT', 'DEFAULT_IP_GROUP', fallback='人机验证')
                    use_type_groups = config.getboolean('DEFAULT', 'USE_TYPE_GROUPS', fallback=True)
                    query_interval = config.getint('DEFAULT', 'QUERY_INTERVAL', fallback=60)
                    max_logs = config.getint('DEFAULT', 'MAX_LOGS_PER_QUERY', fallback=100)
                    debug_mode = config.getboolean('DEFAULT', 'DEBUG_MODE', fallback=False)
                    log_retention_days = config.getint('DEFAULT', 'LOG_RETENTION_DAYS', fallback=30)
                    attack_types_filter = config.get('DEFAULT', 'ATTACK_TYPES_FILTER', fallback='').split(',')
                    attack_types_filter = [t.strip() for t in attack_types_filter if t.strip()]
                    config_reload_interval = config.getint('DEFAULT', 'CONFIG_RELOAD_INTERVAL', fallback=300)
                    
                    # 更新类型组映射
                    if 'TYPE_GROUP_MAPPING' in config:
                        type_group_mapping = dict(config['TYPE_GROUP_MAPPING'])
                    
                    # 更新日志级别
                    if debug_mode:
                        logger.setLevel(logging.DEBUG)
                    
                last_config_reload = current_time
            
            # 检查是否需要清理日志
            if (current_time - last_log_cleanup).days >= 1:
                logger.debug("执行定期日志清理")
                clean_old_logs(log_dir, log_retention_days)
                last_log_cleanup = current_time
            
            # 检查是否需要轮转日志
            if (current_time - last_log_rotation_check).total_seconds() >= 3600:  # 每小时检查一次
                log_file = os.path.join(log_dir, 'auto_blocker.log')
                if check_log_rotation(log_file):
                    # 如果日志已轮转，需要重新设置日志处理器
                    logger, _ = setup_logging()
                last_log_rotation_check = current_time
            
            # 检查是否需要更新攻击类型
            if (current_time - last_attack_types_update).total_seconds() >= 86400:  # 每天更新一次
                update_attack_type_names(api)
                last_attack_types_update = current_time
            
            # 检查是否需要清理缓存
            if (current_time - last_cache_cleanup).total_seconds() >= 3600:  # 每小时清理一次
                api.clean_cache()
                last_cache_cleanup = current_time
            
            # 直接获取最新的攻击日志，不使用时间过滤
            logs = api.get_attack_logs(max_logs)
            
            if logs:
                # 处理日志
                new_logs_count = 0
                for log in logs:
                    # 获取日志ID，如果没有ID则使用其他唯一标识
                    log_id = log.get('id') or f"{log.get('src_ip')}_{log.get('timestamp')}_{log.get('attack_type')}"
                    
                    # 检查是否已处理过该日志
                    if log_id in processed_log_ids:
                        continue
                    
                    # 处理日志
                    process_log_entry(log, api, default_ip_group, use_type_groups, type_group_mapping, attack_types_filter)
                    
                    # 将日志ID添加到已处理集合
                    processed_log_ids.add(log_id)
                    new_logs_count += 1
                    
                    # 如果集合过大，移除最早的一些ID
                    if len(processed_log_ids) > max_processed_ids:
                        # 移除20%的旧ID
                        remove_count = int(max_processed_ids * 0.2)
                        processed_log_ids = set(list(processed_log_ids)[remove_count:])
                
                if new_logs_count > 0:
                    logger.debug(f"处理了 {new_logs_count} 条新的攻击日志")
            
            # 计算本次循环实际耗时
            elapsed_time = time.time() - loop_start_time
            
            # 计算需要等待的时间，确保两次查询之间的间隔不小于query_interval
            wait_time = max(0, query_interval - elapsed_time)
            
            if elapsed_time > query_interval:
                logger.warning(f"处理日志耗时 {elapsed_time:.2f} 秒，超过了设定的查询间隔 {query_interval} 秒")
            
            # 等待下一次查询
            if wait_time > 0:
                time.sleep(wait_time)
            else:
                # 如果处理时间已经超过了间隔时间，立即进行下一次循环，但先让出CPU
                time.sleep(0.1)
        
        except KeyboardInterrupt:
            logger.info("收到中断信号，退出程序")
            break
        
        except Exception as e:
            logger.error(f"API监控时出错: {str(e)}")
            time.sleep(query_interval)
    
    logger.info("API监控已停止")

# 修改main函数，使用新的日志设置
def main():
    """主函数"""
    # 设置日志
    global logger
    logger, log_dir = setup_logging()
    
    parser = argparse.ArgumentParser(description='SafeLine Auto Blocker')
    
    # 添加命令行参数
    parser.add_argument('--api-monitor', action='store_true', help='API监控模式（默认）')
    parser.add_argument('--process-ip', nargs=3, metavar=('IP', 'REASON', 'GROUP'), help='手动添加单个IP到指定IP组')
    parser.add_argument('--filter-type-ids', help='根据攻击类型ID筛选IP，多个ID用逗号分隔')
    parser.add_argument('--list-attack-types', action='store_true', help='获取并显示雷池WAF支持的攻击类型')
    parser.add_argument('--get-logs', help='获取特定攻击类型的日志，多个ID用逗号分隔')
    parser.add_argument('--clean-logs', action='store_true', help='立即清理过期日志文件')
    parser.add_argument('--daemon', action='store_true', help='以守护进程模式运行（仅Linux/Unix）')
    parser.add_argument('--version', action='version', version=f'SafeLine Auto Blocker v{VERSION}')
    
    args = parser.parse_args()
    
    # 解析配置文件
    config = parse_config()
    if not config:
        return
    
    # 如果指定了立即清理日志
    if args.clean_logs:
        log_retention_days = config.getint('DEFAULT', 'LOG_RETENTION_DAYS', fallback=30)
        logger.info(f"手动执行日志清理，保留天数: {log_retention_days}")
        clean_old_logs(log_dir, log_retention_days)
        return
    
    # 如果指定了守护进程模式
    if args.daemon and os.name == 'posix':
        daemonize()
    
    # 如果指定了列出攻击类型
    if args.list_attack_types:
        # 获取配置
        host = config.get('DEFAULT', 'SAFELINE_HOST', fallback='localhost')
        port = config.get('DEFAULT', 'SAFELINE_PORT', fallback='9443')
        encrypted_token = config.get('DEFAULT', 'SAFELINE_TOKEN_ENCRYPTED')
        
        # 读取密钥
        try:
            with open(KEY_FILE, 'r') as f:
                key = f.read().strip()
        except Exception as e:
            logger.error(f"读取密钥文件时出错: {str(e)}")
            return
        
        # 解密令牌
        try:
            token = decrypt_token(encrypted_token, key)
        except Exception as e:
            logger.error(f"解密令牌时出错: {str(e)}")
            return
        
        # 创建API实例
        api = SafeLineAPI(host, port, token)
        
        # 获取攻击类型
        attack_types = api.get_attack_types()
        
        # 显示攻击类型
        print("\n雷池WAF支持的攻击类型:")
        print("ID\t名称")
        print("-" * 20)
        for attack_type in attack_types:
            print(f"{attack_type['id']}\t{attack_type['name']}")
        print()
        
        return
    
    # 如果指定了获取日志
    if args.get_logs:
        # 获取配置
        host = config.get('DEFAULT', 'SAFELINE_HOST', fallback='localhost')
        port = config.get('DEFAULT', 'SAFELINE_PORT', fallback='9443')
        encrypted_token = config.get('DEFAULT', 'SAFELINE_TOKEN_ENCRYPTED')
        max_logs = config.getint('DEFAULT', 'MAX_LOGS_PER_QUERY', fallback=100)
        
        # 读取密钥
        try:
            with open(KEY_FILE, 'r') as f:
                key = f.read().strip()
        except Exception as e:
            logger.error(f"读取密钥文件时出错: {str(e)}")
            return
        
        # 解密令牌
        try:
            token = decrypt_token(encrypted_token, key)
        except Exception as e:
            logger.error(f"解密令牌时出错: {str(e)}")
            return
        
        # 创建API实例
        api = SafeLineAPI(host, port, token)
        
        # 解析攻击类型ID
        attack_type_ids = [id.strip() for id in args.get_logs.split(',') if id.strip()]
        
        # 获取并显示日志
        for attack_type_id in attack_type_ids:
            try:
                attack_type_id = int(attack_type_id)
                attack_type_name = get_attack_type_name(attack_type_id)
                
                print(f"\n获取 {attack_type_name} 类型的攻击日志:")
                logs = api.get_attack_logs(max_logs, attack_type_id)
                
                if logs:
                    print(f"找到 {len(logs)} 条日志:")
                    for log in logs:
                        src_ip = log.get('src_ip', 'N/A')
                        website = log.get('website', 'N/A')
                        timestamp = log.get('timestamp', 'N/A')
                        print(f"IP: {src_ip}, 网站: {website}, 时间: {timestamp}")
                else:
                    print("未找到日志")
            except ValueError:
                print(f"无效的攻击类型ID: {attack_type_id}")
        
        return
    
    # 如果指定了处理单个IP
    if args.process_ip:
        # 获取配置
        host = config.get('DEFAULT', 'SAFELINE_HOST', fallback='localhost')
        port = config.get('DEFAULT', 'SAFELINE_PORT', fallback='9443')
        encrypted_token = config.get('DEFAULT', 'SAFELINE_TOKEN_ENCRYPTED')
        
        # 读取密钥
        try:
            with open(KEY_FILE, 'r') as f:
                key = f.read().strip()
        except Exception as e:
            logger.error(f"读取密钥文件时出错: {str(e)}")
            return
        
        # 解密令牌
        try:
            token = decrypt_token(encrypted_token, key)
        except Exception as e:
            logger.error(f"解密令牌时出错: {str(e)}")
            return
        
        # 创建API实例
        api = SafeLineAPI(host, port, token)
        
        # 获取参数
        ip, reason, group = args.process_ip
        
        # 添加IP到组
        if api.add_ip_to_group(ip, reason, group):
            print(f"成功添加IP {ip} 到 {group} 组")
        else:
            print(f"添加IP {ip} 到 {group} 组失败")
        
        return
    
    # 默认使用API监控模式
    api_monitor(config)

if __name__ == "__main__":
    main()
