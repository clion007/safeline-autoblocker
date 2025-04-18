#!/usr/bin/env python3

"""
API交互模块
"""
import time
import requests
import warnings
from datetime import datetime
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# 禁用不安全请求的警告
warnings.simplefilter('ignore', InsecureRequestWarning)

class SafeLineAPI:
    """雷池WAF API交互类"""
    
    def __init__(self):
        """初始化API客户端"""
        if hasattr(self, '_initialized'):
            return
 
        self._logger = None
        self._configer = None
        self._baseurl = None
        self._token = None
        
        self.session = requests.Session()
        
        # 设置重试策略
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "PUT", "POST", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        
        # 禁用SSL验证
        self.session.verify = False
        
        # IP组缓存
        self.ip_groups_cache = {}
        self.ip_groups_cache_time = None
        
        # 已添加IP缓存
        self.added_ips_cache = {}
        
        # 添加IP批量处理队列
        self.ip_batch_queue = {}
        self.last_batch_process_time = time.time()
        
        self._initialized = True
    
    def get_configer(self):
        """获取配置管理器"""
        if self._configer is None:
            from factory import Factory
            self._configer = Factory.get_configer()
        return self._configer
    
    def get_logger(self):
        """获取日志记录器"""
        if self._logger is None:
            from factory import Factory
            self._logger = Factory.get_logger()
        return self._logger
        
    def get_baseurl(self):
        """获取基础URL"""
        if self._baseurl is None:
            configer = self.get_configer()
            host = configer.get_value('GENERAL', 'SAFELINE_HOST')
            port = configer.get_value('GENERAL', 'SAFELINE_PORT')
            api_prefix = configer.get_value('GENERAL', 'API_PREFIX')

            self.baseurl =f"https://{host}:{port}{api_prefix}"

        return self.baseurl

    def get_token(self):
        """获取API Token"""
        if self._token is None:
            self._token = self.get_configer().get_token()
        
        return self._token

    def reload_token(self):
        """重载API Token"""
        if self._token is not None:
            self._token = None
        self._token = self.get_token()

    def _prepare_url(self, endpoint):
        """准备API请求URL
        
        Args:
            endpoint: API端点路径
            
        Returns:
            str: 完整的API URL
        """
        baseurl = self.get_baseurl()
        url = f"{baseurl}/{endpoint.lstrip('/')}"

        return url
    
    def _prepare_headers(self):
        """准备API请求头
        
        Returns:
            dict: 请求头字典
        """
        token = self.get_token()
        return {
            'X-SLCE-API-TOKEN': token,
            'Content-Type': 'application/json'
        }

    def get_attack_logs(self, attack_type=None):
        """获取攻击日志"""
        url = self._prepare_url('records')
        headers = self._prepare_headers()
        
        # 从配置中获取查询参数
        max_logs_per_page = min(int(self.get_configer().get_value('GENERAL', 'MAX_LOGS_PER_QUERY')), 100)
        max_pages = int(self.get_configer().get_value('GENERAL', 'MAX_PAGES_PER_QUERY'))
        
        all_logs = []
        
        try:
            # 分页获取日志
            for page in range(1, max_pages + 1):
                params = {
                    'page': page,
                    'page_size': max_logs_per_page
                }
                
                if attack_type:
                    params['attack_type'] = attack_type
                
                self.get_logger().debug(f"获取第 {page} 页日志，每页 {max_logs_per_page} 条")
                response = self.session.get(url=url, params=params, headers=headers)
                
                if response.status_code != 200:
                    self.get_logger().error(f"获取日志失败: {response.status_code} - {response.text}")
                    break
                    
                result = response.json()
                data = result.get('data', {}).get('data', [])
                
                if not data:  # 如果没有更多数据，提前退出
                    break
                    
                all_logs.extend(data)
                self.get_logger().debug(f"已获取 {len(all_logs)} 条日志")
            
            return all_logs
            
        except Exception as error:
            self.get_logger().error(f"获取攻击日志异常: {str(error)}")
            return []
    
    def add_ip_to_batch(self, ip, group_name):
        """将IP添加到批处理队列"""
        
        self.get_logger().debug(f"尝试将IP {ip} 添加到组 '{group_name}'")
        
        # 检查缓存中是否已添加该IP
        cache_key = f"{ip}_{group_name}"
        if cache_key in self.added_ips_cache:
            self.get_logger().debug(f"IP {ip} 已在缓存中，跳过添加")
            return True
    
        # 获取IP组信息并检查IP是否已存在
        group_info = self._get_ip_group_info(group_name)
        if group_info and ip in group_info.get('ips', []):
            self.get_logger().debug(f"IP {ip} 已存在于组 '{group_name}' 中，跳过添加")
            return True
        
        # 添加到批处理队列
        if group_name not in self.ip_batch_queue:
            self.ip_batch_queue[group_name] = []
        
        self.ip_batch_queue[group_name].append(ip)
        self.get_logger().debug(f"IP {ip} 已添加到组 '{group_name}' 的处理队列")
        return True
    
    def _update_ip_group(self, group_id, group_name, current_ips, new_ips):
        """更新IP组，添加新IP"""
        url = self._prepare_url(f'ipgroup')
        headers = self._prepare_headers()
        
        data = {
            "id": group_id,
            "comment": group_name,
            "ips": current_ips
        }
        
        try:
            self.get_logger().debug(f"发送更新请求: {data}")
            response = self.session.put(url=url, headers=headers, json=data)
            self.get_logger().debug(f"API响应: {response.text}")
            
            if response.status_code != 200:
                self.get_logger().error(f"API请求失败: {response.status_code} - {response.text}")
                return False

            result = response.json()
                
            if result.get('err'):
                self.get_logger().error(f"API返回错误: {result.get('err')} - {result.get('msg')}")
                return False

            success = response.status_code == 200 and response.json().get('err') is None
            
            if success:
                if len(new_ips) == 1:
                    self.get_logger().info(f"成功添加IP {new_ips[0]} 到组 '{group_name}'")
                else:
                    self.get_logger().info(f"成功批量添加 {len(new_ips)} 个IP到组 '{group_name}'")
                
                # 更新缓存
                for ip in new_ips:
                    cache_key = f"{ip}_{group_name}"
                    self.added_ips_cache[cache_key] = datetime.now()

                # 更新IP组缓存
                if group_name in self.ip_groups_cache:
                    self.ip_groups_cache[group_name]['ips'] = current_ips
                
                return True
            else:
                if len(new_ips) == 1:
                    self.get_logger().error(f"添加IP {new_ips[0]} 到组 '{group_name}' 失败: {response.text}")
                else:
                    self.get_logger().error(f"批量添加IP到组 '{group_name}' 失败: {response.text}")
                return False
                
        except Exception as error:
            if len(new_ips) == 1:
                self.get_logger().error(f"添加IP {new_ips[0]} 到组 '{group_name}' 时出错: {str(error)}")
            else:
                self.get_logger().error(f"批量添加IP到组 '{group_name}' 时出错: {str(error)}")
            return False
    
    def _get_ip_group_info(self, group_name):
        """获取IP组信息，使用缓存减少API请求"""
        
        # 检查缓存是否有效
        current_time = datetime.now()
        cache_clean_interval = int(self.get_configer().get_value('MAINTENANCE', 'CACHE_CLEAN_INTERVAL'))
        if (self.ip_groups_cache_time is not None and 
            (current_time - self.ip_groups_cache_time).total_seconds() < cache_clean_interval and
            group_name in self.ip_groups_cache):
            return self.ip_groups_cache[group_name]
        
        # 缓存无效，重新获取所有IP组
        url = self._prepare_url('ipgroup')
        headers = self._prepare_headers()
        
        try:
            # 1. 首先获取所有IP组列表
            response = self.session.get(url=url, headers=headers)
            if response.status_code != 200:
                self.get_logger().error(f"获取IP组列表失败: {response.status_code} - {response.text}")
                return None
            
            result = response.json()
            if result.get('err'):
                self.get_logger().error(f"API返回错误: {result.get('err')} - {result.get('msg')}")
                return None
            if 'data' not in result or 'nodes' not in result['data']:
                self.get_logger().error("IP组数据格式不正确")
                return None
            
            # 2. 查找目标IP组
            target_group = None
            for group in result['data']['nodes']:
                if group.get('comment') == group_name:
                    target_group = group
                    break
                    
            if not target_group:
                self.get_logger().error(f"未找到名为 {group_name} 的IP组")
                return None
            
            # 3. 获取指定ID的IP组详细信息
            detail_url = self._prepare_url(f"ipgroup/detail?id={target_group.get('id')}")
            detail_response = self.session.get(url=detail_url, headers=headers)
            
            if detail_response.status_code != 200:
                self.get_logger().error(f"获取IP组详细信息失败: {detail_response.status_code} - {detail_response.text}")
                return None
            
            detail_result = detail_response.json()
            if not detail_result.get('data') or not detail_result['data'].get('data'):
                self.get_logger().error("IP组详细信息格式不正确")
                return None
            
            # 4. 使用详细信息更新缓存
            group_info = detail_result['data']['data']
            self.ip_groups_cache[group_name] = group_info
            self.ip_groups_cache_time = current_time
            
            return group_info
                
        except Exception as error:
            self.get_logger().error(f"获取IP组信息异常: {str(error)}")
            return None
    
    def process_ip_batch(self):
        """处理IP批处理队列"""
        if not self.ip_batch_queue:
            return
        
        self.get_logger().debug(f"开始处理IP，共 {sum(len(ips) for ips in self.ip_batch_queue.values())} 个IP")
        
        for group_name, ip_list in self.ip_batch_queue.items():
            if not ip_list:
                continue
                
            # 获取IP组信息
            group_info = self._get_ip_group_info(group_name)
            if not group_info:
                self.get_logger().error(f"未找到IP组 '{group_name}'，跳过添加IP")
                continue
            
            group_id = group_info.get('id')
            current_ips = group_info.get('ips', []).copy()
            
            # 修改为
            new_ips = []
            for ip in ip_list:
                if ip not in current_ips:
                    new_ips.append(ip)
                    current_ips.append(ip)
            
            if not new_ips:
                self.get_logger().debug(f"IP组 '{group_name}' 中没有新IP需要添加")
                continue
            
            self.get_logger().debug(f"准备添加新IP: {new_ips}")
            self.get_logger().debug(f"当前IP组 '{group_name}' 的IP列表: {current_ips}")

            # 批量更新IP组
            self._update_ip_group(group_id, group_name, current_ips, new_ips)
        
        # 清空队列
        self.ip_batch_queue = {}
        self.last_batch_process_time = time.time()
    
    def process_attack_logs(self):
        """处理攻击日志并提取IP"""
        logs = self.get_attack_logs()
        
        if not logs:
            self.get_logger().debug("没有获取到攻击日志")
            return 0
        
        # 处理每条日志
        queued_count = 0
        for log_entry in logs:
            # 提取IP和攻击类型
            ip = log_entry.get('src_ip')
            if not ip:
                continue
                
            attack_type = log_entry.get('attack_type')
            self.get_logger().debug(f"原始攻击类型值: {attack_type}, 类型: {type(attack_type)}")
            
            # 过滤掉黑名单(id=-3)的记录
            if attack_type == -3 or attack_type == '-3':
                self.get_logger().debug(f"跳过黑名单类型(id=-3)的IP {ip}")
                continue
                
            # 获取攻击类型过滤配置
            attack_types_filter = self.get_configer().get_value('GENERAL', 'ATTACK_TYPES_FILTER')
            self.get_logger().debug(f"过滤配置值: {attack_types_filter}")
            
            # 检查攻击类型过滤
            if attack_types_filter:
                try:
                    if not attack_type:
                        self.get_logger().error("攻击类型为空")
                        continue
                        
                    attack_type_int = int(attack_type)
                    filter_types_int = [int(t) for t in attack_types_filter.split(',') if t]
                    
                    self.get_logger().debug(f"转换后的攻击类型: {attack_type_int}, 过滤列表: {filter_types_int}")
                    
                    if attack_type_int not in filter_types_int:
                        self.get_logger().debug(f"跳过攻击类型 {attack_type_int} 的IP {ip}")
                        continue
                except ValueError as e:
                    self.get_logger().error(f"无效的攻击类型值: {attack_type}, 错误: {str(e)}")
                    continue
                
            # 获取对应的IP组
            ip_group = self.get_configer().get_ip_group_for_attack_type(attack_type)
            if not ip_group:
                continue
            
            # 直接将IP添加到批处理队列
            self.add_ip_to_batch(ip, ip_group)
            queued_count += 1
        
        # 强制处理批处理队列
        if queued_count > 0:
            self.process_ip_batch()
        
        return queued_count
    
    def clean_cache(self):
        """清理过期的IP缓存"""
        cache_clean_interval = int(self.get_configer().get_value('MAINTENANCE', 'CACHE_CLEAN_INTERVAL'))
        current_time = datetime.now()
        
        # 清理IP组缓存
        if (self.ip_groups_cache_time is not None and 
            (current_time - self.ip_groups_cache_time).total_seconds() > cache_clean_interval):
            self.ip_groups_cache = {}
            self.ip_groups_cache_time = None
            self.get_logger().debug("已清理IP组缓存")
        expired_keys = []
        
        # 清理已添加IP缓存
        for key, add_time in list(self.added_ips_cache.items()):
            if (current_time - add_time).total_seconds() > cache_clean_interval:
                expired_keys.append(key)
        
        # 删除过期项
        for key in expired_keys:
            del self.added_ips_cache[key]
        
        if expired_keys:
            self.get_logger().debug(f"已清理 {len(expired_keys)} 个过期IP缓存项")
