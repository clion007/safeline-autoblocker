#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SafeLine Auto Blocker
--------------------
自动监控雷池WAF攻击日志并封禁攻击IP。

作者: Clion Nieh
版本: 1.2.0
日期: 2025.4.6
许可证: MIT
"""

import os
import sys
import time
import argparse
from datetime import datetime

# 导入自定义模块
from config import parse_config, PATHS, get_config_values, get_effective_config_file, validate_config
from api import SafeLineAPI, process_log_entry, get_attack_type_name, create_api_instance
from logger import clean_old_logs, logger_manager

# 设置日志 - 使用logger_manager统一管理
logger = logger_manager.get_logger()
log_dir = logger_manager.get_log_dir()

# 添加版本常量
VERSION = "1.2.0"

# 定义时间间隔常量
CACHE_CLEAN_INTERVAL = 3600  # 缓存清理间隔，1小时
LOG_CLEAN_INTERVAL = 86400   # 日志清理间隔，1天
CONFIG_RELOAD_INTERVAL = 300 # 配置重载间隔，5分钟

# 添加辅助函数来处理日志记录器和日志目录
def get_logger_and_dir(logger_instance=None, log_directory=None):
    """获取日志记录器和日志目录"""    
    # 返回日志记录器和日志目录
    return (logger_instance or logger_manager.get_logger()), (log_directory or logger_manager.get_log_dir())

def perform_log_maintenance(current_time, last_times, config_values, api, logger_instance=None, log_directory=None):
    """集中处理日志维护任务"""
    # 获取日志记录器和日志目录
    logger_to_use, log_dir_to_use = get_logger_and_dir(logger_instance, log_directory)
    
    # 检查是否需要清理缓存
    if (current_time - last_times['cache_clean']).total_seconds() > CACHE_CLEAN_INTERVAL:
        logger_to_use.debug("执行缓存清理")
        api.clean_cache()
        last_times['cache_clean'] = current_time
    
    # 检查是否需要清理日志 (可选，因为RotatingFileHandler会自动管理日志文件数量)
    log_retention_days = config_values.get('log_retention_days', 30)
    if log_retention_days > 0 and (current_time - last_times['log_clean']).total_seconds() > LOG_CLEAN_INTERVAL:
        logger_to_use.debug(f"执行额外的日志清理，保留 {log_retention_days} 天")
        # 只传递保留天数参数
        clean_old_logs(retention_days=log_retention_days)
        last_times['log_clean'] = current_time
    
    return last_times

def process_attack_logs(api, config_values, logger_instance=None):
    """处理攻击日志的通用函数"""
    # 获取日志记录器
    logger_to_use = logger_instance or logger_manager.get_logger()
    
    # 获取配置值
    default_ip_group = config_values.get('default_ip_group')
    use_type_groups = config_values.get('use_type_groups')
    type_group_mapping = config_values.get('type_group_mapping', {})
    attack_types_filter = config_values.get('attack_types_filter')
    max_logs = config_values.get('max_logs_per_query')
    
    # 获取攻击日志
    logs = api.get_attack_logs(limit=max_logs)
    
    if not logs:
        logger_to_use.debug("没有新的攻击日志")
        return 0
    
    logger_to_use.debug(f"获取到 {len(logs)} 条攻击日志")
    
    # 处理每条日志
    processed_count = 0
    for log_entry in logs:
        if process_log_entry(log_entry, api, default_ip_group, use_type_groups, 
                            type_group_mapping, attack_types_filter, logger_to_use):
            processed_count += 1
    
    if processed_count > 0:
        logger_to_use.info(f"处理了 {processed_count} 条攻击日志")
    
    return processed_count

def api_monitor(config, logger_instance=None, log_directory=None, existing_api=None):
    """API监控函数"""
    # 使用日志管理器获取日志记录器和日志目录
    logger_to_use, log_dir_to_use = get_logger_and_dir(logger_instance, log_directory)
    
    # 获取配置值
    config_values = get_config_values(config)
    
    # 使用已有API实例或创建新的
    api = existing_api
    if not api:
        api = create_api_instance(config_values, logger_to_use)
        if not api:
            logger_to_use.error("无法创建API实例，监控终止")
            return False
    
    # 初始化上次执行时间记录
    last_times = {
        'query': datetime.now(),
        'config_reload': datetime.now(),
        'cache_clean': datetime.now(),
        'log_clean': datetime.now()
    }
    
    logger_to_use.info("开始API监控模式")
    
    try:
        while True:
            current_time = datetime.now()
            
            # 检查是否需要重新加载配置
            if (current_time - last_times['config_reload']).total_seconds() > CONFIG_RELOAD_INTERVAL:
                logger_to_use.debug("重新加载配置")
                config_file = get_effective_config_file()
                # 保存旧配置值，以便在创建API实例失败时回退
                old_config_values = config_values.copy()
                try:
                    if not config.read(config_file):
                        logger_to_use.warning(f"无法读取配置文件: {config_file}")
                    else:
                        config_values = get_config_values(config)
                        
                        # 重新创建API实例
                        new_api = create_api_instance(config_values, logger_to_use)
                        if new_api:
                            # 如果成功创建新的API实例，替换旧实例
                            api = new_api
                        else:
                            # 如果创建失败，回退到旧配置值
                            logger_to_use.warning("重新创建API实例失败，继续使用旧实例和配置")
                            config_values = old_config_values
                except Exception as error:
                    logger_to_use.error(f"重新加载配置时出错: {str(error)}")
                    # 出错时回退到旧配置
                    config_values = old_config_values
                
                last_times['config_reload'] = current_time
            
            # 检查是否需要查询攻击日志
            query_interval = config_values.get('query_interval')
            if (current_time - last_times['query']).total_seconds() > query_interval:
                process_attack_logs(api, config_values, logger_to_use)
                last_times['query'] = current_time
            
            # 执行日志维护任务
            last_times = perform_log_maintenance(current_time, last_times, config_values, api, logger_to_use, log_dir_to_use)
            
            # 休眠一段时间
            time.sleep(1)
    
    except KeyboardInterrupt:
        logger_to_use.info("收到中断信号，停止监控")
    except Exception as error:
        logger_to_use.error(f"监控过程中发生错误: {str(error)}")
        return False
    
    return True

def main():
    """主函数"""
    # 使用全局logger，避免重复初始化
    global logger, log_dir
    
    # 使用get_effective_config_file()获取配置文件路径
    config_file = get_effective_config_file()
    config = parse_config(config_file)
    if not config:
        logger.error("无法加载配置，程序退出")
        return 1
    
    # 验证配置
    if not validate_config(config, logger):
        logger.error("配置验证失败，程序退出")
        return 1
    
    # 获取配置值（只解析一次配置）
    config_values = get_config_values(config)
    
    parser = argparse.ArgumentParser(description='SafeLine Auto Blocker')
    
    # 添加命令行参数（移除了--api-monitor和--daemon参数）
    parser.add_argument('--list-attack-types', action='store_true', help='获取并显示雷池WAF支持的攻击类型')
    parser.add_argument('--get-logs', help='获取特定攻击类型的日志，多个ID用逗号分隔')
    parser.add_argument('--clean-logs', action='store_true', help='立即清理过期日志文件')
    parser.add_argument('--version', action='store_true', help='显示版本信息')
    
    args = parser.parse_args()
    
    # 显示版本信息
    if args.version:
        print(f"SafeLine Auto Blocker v{VERSION}")
        return 0
    
    # 清理日志
    if args.clean_logs:
        log_retention_days = config_values.get('log_retention_days', 30)
        logger.info(f"手动清理日志，保留 {log_retention_days} 天")
        clean_old_logs(retention_days=log_retention_days)
        return 0
    
    # 创建API实例（只在需要时创建一次）
    api = None
    if not args.version and not args.clean_logs:
        api = create_api_instance(config_values, logger)
        if not api:
            logger.error("无法创建API实例，操作取消")
            # 如果无法创建API实例，直接退出，不仅限于特定命令行参数
            return 1
    
    # 获取攻击类型列表或日志
    if args.list_attack_types or args.get_logs:
        if api:
            if args.list_attack_types:
                attack_types = api.get_attack_types()
                if attack_types:
                    print("\n雷池WAF支持的攻击类型:")
                    print("ID | 名称")
                    print("---|------")
                    for attack_id, attack_name in attack_types.items():
                        print(f"{attack_id} | {attack_name}")
                else:
                    logger.error("获取攻击类型失败")
            
            if args.get_logs:
                attack_types = args.get_logs.split(',')
                for attack_type in attack_types:
                    attack_type = attack_type.strip()
                    try:
                        attack_type_int = int(attack_type)
                        logs = api.get_attack_logs(limit=10, attack_type=attack_type)
                        if logs:
                            attack_type_name = get_attack_type_name(attack_type_int)
                            print(f"\n攻击类型 {attack_type} ({attack_type_name}) 的最新日志:")
                            for log in logs:
                                print(f"IP: {log.get('src_ip')}, 时间: {log.get('time')}, URL: {log.get('website', '')}")
                        else:
                            logger.info(f"未找到攻击类型 {attack_type} 的日志")
                    except ValueError:
                        logger.error(f"无效的攻击类型ID: {attack_type}，必须是整数")
        return 0
    
    # 默认为API监控模式，直接使用已创建的API实例和日志记录器
    result = api_monitor(config, logger, log_dir, api)
    if not result:
        logger.error("API监控模式异常退出")
        return 1  # 返回非零值表示异常退出
    
    return 0

if __name__ == "__main__":
    sys.exit(main() or 0)  # 确保main函数返回值被正确处理
