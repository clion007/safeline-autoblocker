#!/usr/bin/env python3

"""
API交互模块
"""
import time
import requests
from datetime import datetime
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class SafeLineAPI:
    """雷池WAF API交互类"""
    
    def __init__(self, configer, logger):
        """初始化API客户端"""
        if hasattr(self, '_initialized'):
            return
            
        self.logger = logger
        self.configer = configer
        
        # 获取基本配置
        self.token = configer.get_token()
        self.host = configer.get_value('GENERAL', 'SAFELINE_HOST')
        self.port = configer.get_value('GENERAL', 'SAFELINE_PORT')
        self.api_prefix = configer.get_value('GENERAL', 'API_PREFIX')
        
        # 设置参数
        self.cache_expiry = int(configer.get_value('MAINTENANCE', 'CACHE_CLEAN_INTERVAL'))
        self.ip_groups_cache_ttl = int(configer.get_value('GENERAL', 'IP_GROUPS_CACHE_TTL'))
        
        self.session = requests.Session()
        self.headers = {
            'X-SLCE-API-TOKEN': self.token,
            'Content-Type': 'application/json'
        }
        
        # 设置重试策略
        max_retries = int(configer.get_value('GENERAL', 'MAX_RETRIES'))
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
        
        # 已添加IP缓存
        self.added_ips_cache = {}
        
        # 添加IP批量处理队列
        self.ip_batch_queue = {}
        self.last_batch_process_time = time.time()
        
        self._initialized = True
    
    def get_attack_logs(self, attack_type=None):
        """获取攻击日志"""
        url = f"https://{self.host}:{self.port}{self.api_prefix}/records"
        
        # 从配置中获取每次查询的日志数量
        max_logs = self.configer.get_value('GENERAL', 'MAX_LOGS_PER_QUERY')
        
        # 使用page和page_size参数获取最新的日志
        params = {
            'page': 1,
            'page_size': max_logs
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
        except Exception as error:
            self.logger.error(f"获取攻击日志异常: {str(error)}")
            return []
    
    def process_attack_logs(self):
        """处理攻击日志并提取IP"""
        # 获取攻击日志
        logs = self.get_attack_logs()
        
        if not logs:
            self.logger.debug("没有获取到攻击日志")
            return 0
        
        # 处理每条日志
        queued_count = 0
        for log_entry in logs:
            # 提取IP和攻击类型
            ip = log_entry.get('src_ip')
            if not ip:
                continue
                
            attack_type = str(log_entry.get('attack_type'))
            
            # 获取攻击类型过滤配置
            attack_types_filter = self.configer.get_value('GENERAL', 'ATTACK_TYPES_FILTER')
            
            # 检查攻击类型过滤
            if attack_types_filter and attack_type not in attack_types_filter.split(','):
                continue
                
            # 获取对应的IP组
            ip_group = self.configer.get_ip_group_for_attack_type(attack_type)
            if not ip_group:
                continue
            
            # 直接将IP添加到批处理队列
            self.add_ip_to_batch(ip, ip_group)
            queued_count += 1
        
        # 强制处理批处理队列
        if queued_count > 0:
            self.process_ip_batch()
        
        return queued_count
    
    def add_ip_to_batch(self, ip, group_name):
        """将IP添加到批处理队列"""
        
        # 检查缓存中是否已添加该IP
        cache_key = f"{ip}_{group_name}"
        if cache_key in self.added_ips_cache:
            return True

        if group_name not in self.ip_batch_queue:
            self.ip_batch_queue[group_name] = []
        
        # 检查IP是否已在队列中
        for item in self.ip_batch_queue[group_name]:
            if item['ip'] == ip:
                return
        
        # 检查IP是否已在目标IP组中
        group_info = self._get_ip_group_info(group_name)
        if group_info and ip in group_info.get('ips', []):
            self.logger.debug(f"IP {ip} 已存在于组 '{group_name}' 中，跳过添加")
            return
        
        # 添加新IP到队列
        self.ip_batch_queue[group_name].append({
            'ip': ip
        })
        
        # 执行添加IP
        self.process_ip_batch()

    def process_ip_batch(self):
        """处理IP批处理队列"""
        if not self.ip_batch_queue:
            return
        
        self.logger.debug(f"开始处理IP，共 {sum(len(ips) for ips in self.ip_batch_queue.values())} 个IP")
        
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
            
            # 筛选出需要添加的IP
            new_ips = []
            for item in ip_list:
                ip = item['ip']
                if ip not in current_ips:
                    new_ips.append(ip)
                    current_ips.append(ip)
                else:
                    # IP已存在，更新缓存
                    cache_key = f"{ip}_{group_name}"
                    self.added_ips_cache[cache_key] = datetime.now()
            
            if not new_ips:
                self.logger.debug(f"IP组 '{group_name}' 中没有新IP需要添加")
                continue
            
            # 批量更新IP组
            self._update_ip_group(group_id, group_name, current_ips, new_ips)
        
        # 清空队列
        self.ip_batch_queue = {}
        self.last_batch_process_time = time.time()
    
    def _update_ip_group(self, group_id, group_name, current_ips, new_ips):
        """更新IP组，添加新IP"""
        # 使用API更新IP组
        url = f"https://{self.host}:{self.port}{self.api_prefix}/ipgroup"
        
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
                if len(new_ips) == 1:
                    self.logger.info(f"成功添加IP {new_ips[0]} 到组 '{group_name}'")
                else:
                    self.logger.info(f"成功批量添加 {len(new_ips)} 个IP到组 '{group_name}'")
                
                # 更新缓存
                for ip in new_ips:
                    cache_key = f"{ip}_{group_name}"
                    self.added_ips_cache[cache_key] = datetime.now()
                return True
            else:
                if len(new_ips) == 1:
                    self.logger.error(f"添加IP {new_ips[0]} 到组 '{group_name}' 失败: {response.text}")
                else:
                    self.logger.error(f"批量添加IP到组 '{group_name}' 失败: {response.text}")
                return False
        except Exception as error:
            if len(new_ips) == 1:
                self.logger.error(f"添加IP {new_ips[0]} 到组 '{group_name}' 时出错: {str(error)}")
            else:
                self.logger.error(f"批量添加IP到组 '{group_name}' 时出错: {str(error)}")
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
        url = f"https://{self.host}:{self.port}{self.api_prefix}/ipgroup"
        
        try:
            # 确保禁用SSL验证
            response = self.session.get(url, headers=self.headers, verify=False)
            if response.status_code != 200:
                self.logger.error(f"获取IP组列表失败: {response.status_code} - {response.text}")
                return None
            
            result = response.json()
            if 'data' not in result or 'nodes' not in result['data']:
                self.logger.error("IP组数据格式不正确")
                return None
            
            # 更新缓存
            self.ip_groups_cache = {}
            self.ip_groups_cache_time = current_time
            
            for group in result['data']['nodes']:
                if group.get('comment') == group_name:
                    # 获取详细信息
                    detail_url = f"https://{self.host}:{self.port}{self.api_prefix}/ipgroup/detail?id={group.get('id')}"
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
            
            self.logger.error(f"未找到名为 {group_name} 的IP组")
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
