#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import logging
import requests
import argparse
import configparser
import urllib3
import re
import socket
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 全局变量
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = "/etc/safeline/auto_blocker.conf"
LOG_FILE = "/var/log/safeline/auto_blocker.log"
TEMP_DIR = "/tmp"
KEY_FILE = "/etc/safeline/auto_blocker.key"

# 默认配置
# 在全局变量部分添加新的配置项
SAFELINE_HOST = "localhost"
SAFELINE_PORT = 9443
SAFELINE_TOKEN_ENCRYPTED = ""
DEFAULT_IP_GROUP = "人机验证"
USE_TYPE_GROUPS = True
TYPE_GROUP_MAPPING = {}  # 攻击类型ID到IP组的映射
SAFELINE_LOG_FILE = "/var/log/safeline/security.log"
ATTACK_TYPES_FILTER = ""  # 攻击类型过滤，多个ID用逗号分隔
QUERY_INTERVAL = 60
MAX_LOGS_PER_QUERY = 100
FOLLOW_LOG_ROTATION = True
DEBUG_MODE = False
MAX_RETRIES = 3  # API请求最大重试次数
RETRY_BACKOFF_FACTOR = 0.5  # 重试间隔因子
IP_CACHE_EXPIRY = 3600  # IP缓存过期时间（秒）

# IP缓存，避免重复添加
IP_CACHE = {}

# 攻击类型ID映射
ATTACK_TYPE_NAMES = {
    "0": "SQL注入",
    "1": "XSS",
    "2": "CSRF",
    "3": "SSRF",
    "4": "拒绝服务",
    "5": "后门",
    "6": "反序列化",
    "7": "代码执行",
    "8": "代码注入",
    "9": "命令注入",
    "10": "文件上传",
    "11": "文件包含",
    "21": "扫描器",
    "29": "模板注入"
}

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

def log_info(message):
    """记录信息日志"""
    logging.info(message)

def log_error(message):
    """记录错误日志"""
    logging.error(message)

def log_debug(message):
    """记录调试日志"""
    if DEBUG_MODE:
        logging.debug(message)

def load_config():
    """加载配置文件"""
    global SAFELINE_HOST, SAFELINE_PORT, SAFELINE_TOKEN_ENCRYPTED, DEFAULT_IP_GROUP
    global SAFELINE_LOG_FILE, ATTACK_TYPES_FILTER, QUERY_INTERVAL, MAX_LOGS_PER_QUERY
    global FOLLOW_LOG_ROTATION, DEBUG_MODE, USE_TYPE_GROUPS, TYPE_GROUP_MAPPING
    global MAX_RETRIES, RETRY_BACKOFF_FACTOR, IP_CACHE_EXPIRY
    
    if not os.path.exists(CONFIG_FILE):
        log_error(f"配置文件不存在: {CONFIG_FILE}")
        return False
    
    try:
        config = configparser.ConfigParser()
        config.read(CONFIG_FILE)
        
        if 'DEFAULT' in config:
            SAFELINE_HOST = config['DEFAULT'].get('SAFELINE_HOST', SAFELINE_HOST)
            SAFELINE_PORT = config['DEFAULT'].getint('SAFELINE_PORT', SAFELINE_PORT)
            SAFELINE_TOKEN_ENCRYPTED = config['DEFAULT'].get('SAFELINE_TOKEN_ENCRYPTED', SAFELINE_TOKEN_ENCRYPTED)
            DEFAULT_IP_GROUP = config['DEFAULT'].get('DEFAULT_IP_GROUP', DEFAULT_IP_GROUP)
            USE_TYPE_GROUPS = config['DEFAULT'].getboolean('USE_TYPE_GROUPS', USE_TYPE_GROUPS)
            SAFELINE_LOG_FILE = config['DEFAULT'].get('SAFELINE_LOG_FILE', SAFELINE_LOG_FILE)
            ATTACK_TYPES_FILTER = config['DEFAULT'].get('ATTACK_TYPES_FILTER', ATTACK_TYPES_FILTER)
            QUERY_INTERVAL = config['DEFAULT'].getint('QUERY_INTERVAL', QUERY_INTERVAL)
            MAX_LOGS_PER_QUERY = config['DEFAULT'].getint('MAX_LOGS_PER_QUERY', MAX_LOGS_PER_QUERY)
            FOLLOW_LOG_ROTATION = config['DEFAULT'].getboolean('FOLLOW_LOG_ROTATION', FOLLOW_LOG_ROTATION)
            DEBUG_MODE = config['DEFAULT'].getboolean('DEBUG_MODE', DEBUG_MODE)
            MAX_RETRIES = config['DEFAULT'].getint('MAX_RETRIES', MAX_RETRIES)
            RETRY_BACKOFF_FACTOR = config['DEFAULT'].getfloat('RETRY_BACKOFF_FACTOR', RETRY_BACKOFF_FACTOR)
            IP_CACHE_EXPIRY = config['DEFAULT'].getint('IP_CACHE_EXPIRY', IP_CACHE_EXPIRY)
        
        # 加载攻击类型IP组映射
        if USE_TYPE_GROUPS and 'TYPE_GROUP_MAPPING' in config:
            TYPE_GROUP_MAPPING = dict(config['TYPE_GROUP_MAPPING'])
            log_info(f"已加载 {len(TYPE_GROUP_MAPPING)} 个攻击类型IP组映射")
        
        # 验证配置
        if not validate_config():
            log_error("配置验证失败，请检查配置文件")
            return False
        
        log_info("配置文件加载成功")
        return True
    
    except Exception as e:
        log_error(f"加载配置文件异常: {str(e)}")
        return False

def validate_config():
    """验证配置有效性"""
    # 验证主机和端口
    if not SAFELINE_HOST or not SAFELINE_PORT:
        log_error("无效的主机或端口配置")
        return False
    
    # 验证API令牌
    if not SAFELINE_TOKEN_ENCRYPTED:
        log_error("API令牌未配置")
        return False
    
    # 验证IP组名称
    if not DEFAULT_IP_GROUP:
        log_error("默认IP组名称未配置")
        return False
    
    # 验证日志文件路径
    if not os.path.exists(os.path.dirname(SAFELINE_LOG_FILE)):
        log_error(f"日志文件目录不存在: {os.path.dirname(SAFELINE_LOG_FILE)}")
        return False
    
    # 验证查询间隔
    if QUERY_INTERVAL < 10:
        log_error(f"查询间隔过短: {QUERY_INTERVAL}秒，可能导致API过载")
        return False
    
    return True

def decrypt_token(encrypted_token):
    """解密API令牌"""
    if not encrypted_token:
        return ""
    
    try:
        if not os.path.exists(KEY_FILE):
            log_error(f"密钥文件不存在: {KEY_FILE}")
            return ""
        
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
        
        cipher_suite = Fernet(key)
        decrypted_token = cipher_suite.decrypt(encrypted_token.encode()).decode()
        return decrypted_token
    
    except Exception as e:
        log_error(f"解密令牌异常: {str(e)}")
        return ""

def create_session():
    """创建带有重试机制的会话"""
    session = requests.Session()
    
    # 定义重试策略
    retry_strategy = requests.adapters.Retry(
        total=MAX_RETRIES,
        backoff_factor=RETRY_BACKOFF_FACTOR,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    
    adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.verify = False
    
    return session

def is_valid_ip(ip):
    """验证IP地址格式"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_ip_in_cache(ip, ip_group):
    """检查IP是否在缓存中"""
    cache_key = f"{ip}:{ip_group}"
    if cache_key in IP_CACHE:
        # 检查缓存是否过期
        if time.time() - IP_CACHE[cache_key] < IP_CACHE_EXPIRY:
            return True
        else:
            # 缓存过期，删除
            del IP_CACHE[cache_key]
    return False

def add_ip_to_cache(ip, ip_group):
    """将IP添加到缓存"""
    cache_key = f"{ip}:{ip_group}"
    IP_CACHE[cache_key] = time.time()

def query_security_logs(token, start_time=None, end_time=None):
    """查询安全日志
    
    Args:
        token: API令牌
        start_time: 开始时间，格式为"YYYY-MM-DD HH:MM:SS"
        end_time: 结束时间，格式为"YYYY-MM-DD HH:MM:SS"
    
    Returns:
        日志列表
    """
    # 如果未指定时间范围，默认查询最近一小时的日志
    if not start_time:
        start_time = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    if not end_time:
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    log_info(f"查询时间范围: {start_time} 至 {end_time}")
    
    headers = {
        "X-SLCE-API-TOKEN": token,
        "Content-Type": "application/json"
    }
    
    # 构建API请求URL
    url = f"https://{SAFELINE_HOST}:{SAFELINE_PORT}/api/open/records"
    
    # 构建查询参数
    params = {
        "page": 1,
        "page_size": MAX_LOGS_PER_QUERY,
        "start_time": start_time,
        "end_time": end_time
    }
    
    # 如果配置了攻击类型过滤，添加到查询参数中
    if ATTACK_TYPES_FILTER:
        params["attack_type"] = ATTACK_TYPES_FILTER
        log_info(f"使用攻击类型过滤: {ATTACK_TYPES_FILTER}")
    
    try:
        # 创建带有重试机制的会话
        session = create_session()
        
        # 发送API请求
        response = session.get(
            url,
            headers=headers,
            params=params
        )
        
        if response.status_code != 200:
            log_error(f"查询安全日志失败: HTTP {response.status_code}")
            return []
        
        # 解析响应数据
        data = response.json()
        
        if 'data' not in data:
            log_error("查询安全日志失败: 响应格式不正确")
            return []
        
        logs = data.get('data', {}).get('list', [])
        total = data.get('data', {}).get('total', 0)
        
        log_info(f"成功获取 {len(logs)} 条日志，总共 {total} 条")
        return logs
    
    except Exception as e:
        log_error(f"查询安全日志异常: {str(e)}")
        return []

def get_attack_types(token):
    """获取雷池WAF支持的攻击类型列表"""
    log_info("正在获取攻击类型信息...")
    
    # 首先尝试使用本地定义的攻击类型
    if ATTACK_TYPE_NAMES:
        log_info("使用本地定义的攻击类型信息:")
        for attack_id, attack_name in ATTACK_TYPE_NAMES.items():
            log_info(f"攻击类型ID: {attack_id}, 名称: {attack_name}")
        
        # 构建与API返回格式相似的数据结构
        attack_types = [{"id": int(id), "name": name} for id, name in ATTACK_TYPE_NAMES.items()]
        return attack_types
    
    # 如果本地定义为空，则从API获取
    headers = {
        "X-SLCE-API-TOKEN": token,
        "Content-Type": "application/json"
    }
    
    try:
        # 创建带有重试机制的会话
        session = create_session()
        
        response = session.get(
            f"https://{SAFELINE_HOST}:{SAFELINE_PORT}/api/open/security/attack-types",
            headers=headers
        )
        
        if response.status_code != 200:
            log_error(f"获取攻击类型信息失败: HTTP {response.status_code}")
            return []
            
        data = response.json()
        
        if 'data' not in data:
            log_error(f"获取攻击类型信息失败: 响应格式不正确")
            return []
        
        attack_types = data.get('data', [])
        log_info(f"成功获取 {len(attack_types)} 种攻击类型信息")
        
        # 打印攻击类型信息
        for attack_type in attack_types:
            log_info(f"攻击类型ID: {attack_type.get('id')}, 名称: {attack_type.get('name')}")
        
        return attack_types
    
    except Exception as e:
        log_error(f"获取攻击类型信息异常: {str(e)}")
        return []

def get_filtered_logs(token, attack_type_ids, page=1, page_size=20):
    """获取特定攻击类型的日志"""
    log_info(f"正在获取攻击类型ID为 {attack_type_ids} 的日志...")
    
    headers = {
        "X-SLCE-API-TOKEN": token,
        "Content-Type": "application/json"
    }
    
    # 构建查询参数
    params = {
        "page": page,
        "page_size": page_size,
        "attack_type": attack_type_ids
    }
    
    try:
        # 创建带有重试机制的会话
        session = create_session()
        
        response = session.get(
            f"https://{SAFELINE_HOST}:{SAFELINE_PORT}/api/open/records",
            headers=headers,
            params=params
        )
        
        if response.status_code != 200:
            log_error(f"获取过滤日志失败: HTTP {response.status_code}")
            return []
            
        data = response.json()
        
        if 'data' not in data:
            log_error(f"获取过滤日志失败: 响应格式不正确")
            return []
        
        logs = data.get('data', {}).get('list', [])
        total = data.get('data', {}).get('total', 0)
        log_info(f"成功获取 {len(logs)} 条日志，总共 {total} 条")
        
        # 打印日志信息
        for log in logs:
            ip = log.get('client_ip', 'Unknown')
            attack_type = log.get('attack_type_name', 'Unknown')
            url = log.get('url', 'Unknown')
            time = log.get('time', 'Unknown')
            log_info(f"时间: {time}, IP: {ip}, 攻击类型: {attack_type}, URL: {url}")
        
        return logs
    
    except Exception as e:
        log_error(f"获取过滤日志异常: {str(e)}")
        return []

def process_logs(token, logs):
    """处理日志，提取攻击IP并添加到黑名单"""
    if not logs:
        log_info("没有新的日志需要处理")
        return
    
    log_info(f"开始处理 {len(logs)} 条日志")
    
    # 按攻击类型分组提取攻击IP
    attack_ips_by_type = {}
    
    for log_entry in logs:
        ip = log_entry.get('client_ip')
        if not ip or not is_valid_ip(ip):
            log_debug(f"跳过无效IP: {ip}")
            continue
        
        # 获取攻击类型ID和名称
        attack_type_id = str(log_entry.get('attack_type', '0'))
        attack_type_name = log_entry.get('attack_type_name', '未知攻击')
        if not attack_type_name and attack_type_id in ATTACK_TYPE_NAMES:
            attack_type_name = ATTACK_TYPE_NAMES[attack_type_id]
        
        attack_info = f"{attack_type_name}(ID:{attack_type_id})"
        
        # 获取攻击URL
        url = log_entry.get('url', '未知URL')
        
        # 记录详细的攻击信息
        log_info(f"检测到攻击: IP={ip}, 类型={attack_info}, URL={url}")
        
        # 按攻击类型分组
        if attack_type_id not in attack_ips_by_type:
            attack_ips_by_type[attack_type_id] = {}
        
        if ip in attack_ips_by_type[attack_type_id]:
            attack_ips_by_type[attack_type_id][ip]['count'] += 1
            attack_ips_by_type[attack_type_id][ip]['urls'].add(url)
        else:
            attack_ips_by_type[attack_type_id][ip] = {
                'count': 1,
                'type_name': attack_type_name,
                'urls': {url}
            }
    
    # 处理每种攻击类型的IP
    for attack_type_id, ips in attack_ips_by_type.items():
        # 确定使用哪个IP组
        ip_group = DEFAULT_IP_GROUP
        if USE_TYPE_GROUPS and attack_type_id in TYPE_GROUP_MAPPING:
            ip_group = TYPE_GROUP_MAPPING[attack_type_id]
            log_info(f"攻击类型 {attack_type_id} 使用IP组: {ip_group}")
        
        # 添加IP到对应的IP组
        for ip, info in ips.items():
            # 检查IP是否已在缓存中
            if is_ip_in_cache(ip, ip_group):
                log_info(f"跳过已处理的IP: {ip}, IP组: {ip_group}")
                continue
                
            attack_urls = ', '.join(list(info['urls'])[:3])  # 最多显示3个URL
            if len(info['urls']) > 3:
                attack_urls += f" 等{len(info['urls'])}个URL"
                
            reason = f"自动封禁: 攻击类型={info['type_name']}, 攻击URL={attack_urls}, 攻击次数={info['count']}"
            log_info(f"封禁IP: {ip}, IP组: {ip_group}, 原因: {reason}")
            
            # 添加IP到指定IP组
            if add_ip_to_blacklist(token, ip, ip_group, reason[:200]):
                # 添加成功，将IP加入缓存
                add_ip_to_cache(ip, ip_group)

def add_ip_to_blacklist(token, ip, ip_group, reason):
    """添加IP到指定IP组"""
    # 验证IP地址格式
    if not is_valid_ip(ip):
        log_error(f"无效的IP地址格式: {ip}")
        return False
        
    log_info(f"添加IP到IP组: {ip}, IP组: {ip_group}, 原因: {reason}")
    
    headers = {
        "X-SLCE-API-TOKEN": token,
        "Content-Type": "application/json"
    }
    
    # 构建请求数据
    data = {
        "group_name": ip_group,
        "ip": ip,
        "comment": reason
    }
    
    try:
        # 创建带有重试机制的会话
        session = create_session()
        
        # 发送API请求
        response = session.post(
            f"https://{SAFELINE_HOST}:{SAFELINE_PORT}/api/open/security/ip-group/add",
            headers=headers,
            json=data
        )
        
        if response.status_code == 200:
            log_info(f"成功添加IP到IP组: {ip}, IP组: {ip_group}")
            return True
        else:
            log_error(f"添加IP到IP组失败: HTTP {response.status_code}, 响应: {response.text}")
            return False
    
    except Exception as e:
        log_error(f"添加IP到IP组异常: {str(e)}")
        return False

def process_single_ip(token, ip, reason=None, ip_group=None):
    """处理单个IP，添加到指定IP组"""
    # 验证IP地址格式
    if not is_valid_ip(ip):
        log_error(f"无效的IP地址格式: {ip}")
        return False
        
    if not reason:
        reason = "手动添加"
    
    if not ip_group:
        ip_group = DEFAULT_IP_GROUP
    
    log_info(f"手动添加IP到IP组: {ip}, IP组: {ip_group}, 原因: {reason}")
    
    # 检查IP是否已在缓存中
    if is_ip_in_cache(ip, ip_group):
        log_info(f"IP已在IP组中: {ip}, IP组: {ip_group}")
        return True
        
    # 添加IP到指定IP组
    if add_ip_to_blacklist(token, ip, ip_group, reason):
        # 添加成功，将IP加入缓存
        add_ip_to_cache(ip, ip_group)
        return True
    return False

def process_log_line(token, line):
    """处理单行日志"""
    try:
        # 解析日志行
        log_data = json.loads(line)
        
        # 提取IP和攻击类型
        ip = log_data.get('client_ip')
        if not ip or not is_valid_ip(ip):
            log_debug(f"跳过无效IP: {ip}")
            return
            
        attack_type_id = str(log_data.get('attack_type', '0'))
        attack_type_name = log_data.get('attack_type_name', '未知攻击')
        if not attack_type_name and attack_type_id in ATTACK_TYPE_NAMES:
            attack_type_name = ATTACK_TYPE_NAMES[attack_type_id]
        
        # 确定使用哪个IP组
        ip_group = DEFAULT_IP_GROUP
        if USE_TYPE_GROUPS and attack_type_id in TYPE_GROUP_MAPPING:
            ip_group = TYPE_GROUP_MAPPING[attack_type_id]
        
        # 检查IP是否已在缓存中
        if is_ip_in_cache(ip, ip_group):
            log_info(f"跳过已处理的IP: {ip}, IP组: {ip_group}")
            return
            
        log_info(f"发现攻击IP: {ip}, 攻击类型: {attack_type_name}, IP组: {ip_group}")
        
        # 添加IP到指定IP组
        if add_ip_to_blacklist(token, ip, ip_group, f"自动封禁: {attack_type_name}"):
            # 添加成功，将IP加入缓存
            add_ip_to_cache(ip, ip_group)
    
    except json.JSONDecodeError:
        log_debug(f"无法解析日志行: {line}")
    except Exception as e:
        log_error(f"处理日志行异常: {str(e)}")

def verify_ip_groups(token):
    """验证IP组是否存在"""
    log_info("验证IP组是否存在...")
    
    headers = {
        "X-SLCE-API-TOKEN": token,
        "Content-Type": "application/json"
    }
    
    try:
        # 创建带有重试机制的会话
        session = create_session()
        
        # 获取IP组列表
        response = session.get(
            f"https://{SAFELINE_HOST}:{SAFELINE_PORT}/api/open/security/ip-groups",
            headers=headers
        )
        
        if response.status_code != 200:
            log_error(f"获取IP组列表失败: HTTP {response.status_code}")
            return False
            
        data = response.json()
        
        if 'data' not in data:
            log_error("获取IP组列表失败: 响应格式不正确")
            return False
            
        ip_groups = data.get('data', [])
        ip_group_names = [group.get('name') for group in ip_groups]
        
        log_info(f"已获取IP组列表: {', '.join(ip_group_names)}")
        
        # 验证默认IP组
        if DEFAULT_IP_GROUP not in ip_group_names:
            log_error(f"默认IP组不存在: {DEFAULT_IP_GROUP}")
            return False
            
        # 验证攻击类型映射中的IP组
        if USE_TYPE_GROUPS:
            for attack_type_id, ip_group in TYPE_GROUP_MAPPING.items():
                if ip_group not in ip_group_names:
                    log_error(f"攻击类型 {attack_type_id} 对应的IP组不存在: {ip_group}")
                    return False
        
        log_info("IP组验证成功")
        return True
        
    except Exception as e:
        log_error(f"验证IP组异常: {str(e)}")
        return False

def monitor_log_file(token, log_file):
    """监控日志文件"""
    log_info("监控日志文件")
    
    try:
        while True:
            current_time = datetime.now()
            
            # 查询从上次查询到现在的日志
            start_time = last_query_time.strftime("%Y-%m-%d %H:%M:%S")
            end_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
            
            logs = query_security_logs(token, start_time, end_time)
            process_logs(token, logs)
            
            # 更新上次查询时间
            last_query_time = current_time
            
            # 等待下一次查询
            log_info(f"等待 {QUERY_INTERVAL} 秒后进行下一次查询")
            time.sleep(QUERY_INTERVAL)
    
    except KeyboardInterrupt:
        log_info("收到中断信号，退出程序")
    except Exception as e:
        log_error(f"主循环异常: {str(e)}")

def main():
    """主函数"""
    log_info("启动雷池WAF自动封禁工具")
    
    # 加载配置
    config = load_config()
    if not config:
        log_error("加载配置文件失败，使用默认配置")
    
    # 解密令牌
    token = decrypt_token(SAFELINE_TOKEN_ENCRYPTED)
    if not token:
        log_error("API令牌为空或解密失败，请检查配置")
        sys.exit(1)
    
    # 记录进程ID到文件
    with open(os.path.join(TEMP_DIR, "safeline_auto_blocker.pid"), 'w') as f:
        f.write(str(os.getpid()))
    
    # 验证IP组
    if not verify_ip_groups(token):
        log_error("IP组验证失败，请检查雷池WAF中是否存在配置的IP组")
        sys.exit(1)
    
    # 检查命令行参数
    if len(sys.argv) > 1:
        # 默认模式：API监控
        main_loop()

def main_loop():
    """主循环，定期查询安全日志并处理"""
    log_info("启动API监控模式")
    
    # 解密令牌
    token = decrypt_token(SAFELINE_TOKEN_ENCRYPTED)
    if not token:
        log_error("API令牌为空或解密失败，请检查配置")
        return
    
    # 记录上次查询时间
    last_query_time = datetime.now() - timedelta(minutes=5)
    
    try:
        while True:
            current_time = datetime.now()
            
            # 查询从上次查询到现在的日志
            start_time = last_query_time.strftime("%Y-%m-%d %H:%M:%S")
            end_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
            
            logs = query_security_logs(token, start_time, end_time)
            process_logs(token, logs)
            
            # 更新上次查询时间
            last_query_time = current_time
            
            # 等待下一次查询
            log_info(f"等待 {QUERY_INTERVAL} 秒后进行下一次查询")
            time.sleep(QUERY_INTERVAL)
    
    except KeyboardInterrupt:
        log_info("收到中断信号，退出程序")
    except Exception as e:
        log_error(f"主循环异常: {str(e)}")

if __name__ == "__main__":
    main()