#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API交互模块
"""

import os
import sys
import json
import time
import logging
import requests
from datetime import datetime
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# 导入路径常量
from config import PATHS

# 获取日志记录器
logger = logging.getLogger(__name__)

# 定义攻击类型常量映射
ATTACK_TYPES = {
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

# 全局常量定义
# 缓存过期时间（秒）
CACHE_EXPIRY = 3600  # 1小时
# IP批处理阈值
IP_BATCH_SIZE = 20
# IP批处理时间间隔（秒）
IP_BATCH_INTERVAL = 10
# IP组缓存有效期（秒）
IP_GROUP_CACHE_TTL = 300  # 5分钟

# 全局变量，用于存储攻击类型名称
attack_type_names = {}
# IP缓存，避免重复添加
ip_cache = {}

# 在文件顶部导入日志管理器
from logger import logger_manager

class SafeLineAPI:
    """雷池WAF API交互类"""
    
    def __init__(self, host, port, token, logger_instance=None):
        """初始化API实例"""
        self.host = host
        self.port = port
        self.token = token
        # 使用日志管理器获取日志记录器
        self.logger = logger_instance or logger_manager.get_logger()
        
        self.headers = {
            'X-SLCE-API-TOKEN': self.token,
            'Content-Type': 'application/json'
        }
        
        # 设置日志记录器
        self.logger = logger_instance or logger
        
        # 设置重试策略
        self.session = requests.Session()
        # 禁用SSL警告
        requests.packages.urllib3.disable_warnings()
        # 禁用SSL验证
        self.session.verify = False
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
        self.ip_groups_cache_ttl = ip_group_cache_ttl
        
        # 已添加IP缓存
        self.added_ips_cache = {}
        
        # 添加IP批量处理队列
        self.ip_batch_queue = {}
        self.last_batch_process_time = time.time()
        
        # 缓存配置
        self.ip_batch_size = ip_batch_size
        self.ip_batch_interval = ip_batch_interval
        self.cache_expiry = cache_expiry
    
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
            # 确保禁用SSL验证
            response = self.session.get(url, params=params, headers=self.headers, verify=False)
            if response.status_code == 200:
                result = response.json()
                data = result.get('data', {}).get('data', [])
                return data
            else:
                self.logger.error(f"获取攻击日志失败: {response.status_code} - {response.text}")
                return []
        except Exception as error:  # 修改: 使用更具描述性的变量名
            self.logger.error(f"获取攻击日志异常: {str(error)}")
            return []
    
    def add_ip_to_batch(self, ip, reason, group_name):
        """将IP添加到批处理队列"""
        if group_name not in self.ip_batch_queue:
            self.ip_batch_queue[group_name] = []
        
        # 检查IP是否已在队列中
        for item in self.ip_batch_queue[group_name]:
            if item['ip'] == ip:
                # 更新原因
                item['reason'] = reason
                return
        
        # 添加新IP到队列
        self.ip_batch_queue[group_name].append({
            'ip': ip,
            'reason': reason
        })
        
        # 检查是否需要处理批量队列
        current_time = time.time()
        if (current_time - self.last_batch_process_time > self.ip_batch_interval) or sum(len(ips) for ips in self.ip_batch_queue.values()) >= self.ip_batch_size:
            self.process_ip_batch()

    def process_ip_batch(self):
        """处理IP批处理队列"""
        if not self.ip_batch_queue:
            return
        
        self.logger.debug(f"开始批量处理IP，共 {sum(len(ips) for ips in self.ip_batch_queue.values())} 个IP")
        
        for group_name, ip_list in self.ip_batch_queue.items():
            if not ip_list:
                continue
                
            # 获取IP组信息
            group_info = self._get_ip_group_info(group_name)
            if not group_info:
                self.logger.error(f"未找到IP组 '{group_name}'，跳过添加IP")
                continue
            
            group_id = group_info.get('id')
            current_ips = group_info.get('ips', []).copy()
            
            # 添加新IP到列表
            added_count = 0
            for item in ip_list:
                ip = item['ip']
                if ip not in current_ips:
                    current_ips.append(ip)
                    added_count += 1
            
            if added_count == 0:
                self.logger.debug(f"IP组 '{group_name}' 中没有新IP需要添加")
                continue
            
            # 使用现有API更新IP组
            url = f"https://{self.host}:{self.port}/api/open/ipgroup"
            
            data = {
                "id": group_id,
                "comment": group_name,
                "reference": "",
                "ips": current_ips
            }
            
            try:
                # 确保禁用SSL验证
                response = self.session.put(url, headers=self.headers, json=data, verify=False)
                success = response.status_code == 200 and response.json().get('err') is None
                
                if success:
                    self.logger.info(f"成功批量添加 {added_count} 个IP到组 '{group_name}'")
                    # 更新缓存
                    for item in ip_list:
                        cache_key = f"{item['ip']}_{group_name}"
                        self.added_ips_cache[cache_key] = datetime.now()
                else:
                    self.logger.error(f"批量添加IP到组 '{group_name}' 失败: {response.text}")
            except Exception as error:  # 修改: 使用更具描述性的变量名
                self.logger.error(f"批量添加IP到组 '{group_name}' 时出错: {str(error)}")
        
        # 清空队列
        self.ip_batch_queue = {}
        self.last_batch_process_time = time.time()

    def add_ip_to_group(self, ip, reason, group_name):
        """添加IP到指定IP组（使用批处理）"""
        # 检查缓存中是否已添加该IP
        cache_key = f"{ip}_{group_name}"
        if cache_key in self.added_ips_cache:
            return True
        
        # 将IP添加到批处理队列
        self.add_ip_to_batch(ip, reason, group_name)
        return True
    
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
            # 确保禁用SSL验证
            response = self.session.get(url, headers=self.headers, verify=False)
            if response.status_code != 200:
                self.logger.error(f"获取IP组列表失败: {response.status_code} - {response.text}")
                return None
            
            result = response.json()
            if 'data' not in result or 'nodes' not in result['data']:
                self.logger.error("IP组数据格式不正确")  # 修改：使用self.logger替代logger
                return None
            
            # 更新缓存
            self.ip_groups_cache = {}
            self.ip_groups_cache_time = current_time
            
            for group in result['data']['nodes']:
                if group.get('comment') == group_name:
                    # 获取详细信息
                    detail_url = f"https://{self.host}:{self.port}/api/open/ipgroup/detail?id={group.get('id')}"
                    # 确保禁用SSL验证
                    detail_response = self.session.get(detail_url, headers=self.headers, verify=False)
                    
                    if detail_response.status_code == 200:
                        detail_result = detail_response.json()
                        if 'data' in detail_result and 'data' in detail_result['data']:
                            group_info = detail_result['data']['data']
                            self.ip_groups_cache[group_name] = group_info
                            return group_info
                    
                    self.ip_groups_cache[group_name] = group
                    return group
            
            self.logger.error(f"未找到名为 {group_name} 的IP组")  # 修改：使用self.logger替代logger
            return None
        
        except Exception as error:
            self.logger.error(f"获取IP组信息异常: {str(error)}")
            return None
    
    def clean_cache(self):
        """清理过期的IP缓存"""
        current_time = datetime.now()
        expired_keys = []
        
        # 查找过期的缓存项
        for key, timestamp in self.added_ips_cache.items():
            if (current_time - timestamp).total_seconds() > self.cache_expiry:
                expired_keys.append(key)
        
        # 删除过期项
        for key in expired_keys:
            del self.added_ips_cache[key]
        
        if expired_keys:
            self.logger.debug(f"已清理 {len(expired_keys)} 个过期IP缓存项")

# 攻击类型名称缓存
attack_type_names = {}

# 初始化攻击类型名称缓存
for attack_id, attack_name in ATTACK_TYPES.items():
    attack_type_names[str(attack_id)] = attack_name

# 移除 update_attack_type_names 函数

# 修改 get_attack_type_name 函数，简化实现
def get_attack_type_name(attack_type_id, attack_type_names_dict=None):
    """获取攻击类型名称，使用缓存提高性能"""
    # 将 attack_type_id 转换为字符串
    attack_type_id = str(attack_type_id)
    
    # 如果没有提供字典，使用全局变量
    if attack_type_names_dict is None:
        global attack_type_names
        attack_type_names_dict = attack_type_names
    
    # 如果缓存中有，直接返回
    if attack_type_id in attack_type_names_dict:
        return attack_type_names_dict[attack_type_id]
    
    # 否则返回未知类型
    return f"未知类型({attack_type_id})"

# 修改 process_log_entry 函数
def process_log_entry(log_entry, api, default_ip_group, use_type_groups, type_group_mapping, attack_types_filter, logger_instance=None, attack_type_names_dict=None):
    """处理单个日志条目"""
    # 使用日志管理器获取日志记录器
    logger_to_use = logger_instance or logger_manager.get_logger()
    
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
        attack_type_name = get_attack_type_name(attack_type, attack_type_names_dict)
        reason = f"未列举攻击类型: {attack_type_name} - {url}"
        return api.add_ip_to_group(ip, reason, default_ip_group)
    
    # 获取攻击类型名称
    attack_type_name = get_attack_type_name(attack_type, attack_type_names_dict)
    
    # 确定IP组
    ip_group = default_ip_group
    if use_type_groups and str(attack_type) in type_group_mapping:
        ip_group = type_group_mapping[str(attack_type)]
    
    # 构建原因
    reason = f"{attack_type_name} - {url}"
    
    # 添加IP到IP组
    return api.add_ip_to_group(ip, reason, ip_group)

def create_api_instance(config_values, logger_instance=None):
    """创建API实例"""
    # 使用日志管理器获取日志记录器
    logger_to_use = logger_instance or logger_manager.get_logger()
    
    # 获取配置值
    host = config_values.get('safeline_host', 'localhost')
    port = config_values.get('safeline_port', 9443)
    token = config_values.get('safeline_token_encrypted', '')
    
    # 如果令牌是加密的，尝试解密
    if token.startswith('gAAAAAB'):
        try:
            # 修改: 使用get_effective_key_file()获取密钥文件路径
            from config import get_effective_key_file, decrypt_token
            key_file_path = get_effective_key_file()
            with open(key_file_path, 'r') as key_file:
                key = key_file.read().strip()
            token = decrypt_token(token, key)
        except Exception as error:
            logger_to_use.error(f"解密令牌失败: {str(error)}")
            return None
    
    # 创建API实例
    try:
        api = SafeLineAPI(
            host=host,
            port=port,
            token=token,
            logger_instance=logger_to_use
        )
        
        # 设置自定义参数
        if 'ip_batch_size' in config_values:
            api.ip_batch_size = config_values['ip_batch_size']
        if 'ip_batch_interval' in config_values:
            api.ip_batch_interval = config_values['ip_batch_interval']
        if 'cache_expiry' in config_values:
            api.cache_expiry = config_values['cache_expiry']
        if 'ip_groups_cache_ttl' in config_values:
            api.ip_groups_cache_ttl = config_values['ip_groups_cache_ttl']
        
        logger_to_use.info(f"成功创建API实例，连接到 {host}:{port}")
        return api
    except Exception as error:
        logger_to_use.error(f"创建API实例失败: {str(error)}")
        return None
