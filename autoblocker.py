#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SafeLine AutoBlocker
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
from datetime import datetime, timedelta

# 导入自定义模块
from config import (
    parse_config, validate_config, get_config_values, 
    CONFIG_FILE, LOG_DIR, LOG_FILE, VERSION
)
from api import SafeLineAPI, process_log_entry, get_attack_type_name, create_api_instance
from logger import clean_old_logs, logger_manager

# 设置日志 - 使用logger_manager统一管理
logger = logger_manager.get_logger()
log_dir = logger_manager.get_log_dir()

# 定义时间间隔常量
CACHE_CLEAN_INTERVAL = 3600  # 缓存清理间隔，1小时
LOG_CLEAN_INTERVAL = 86400   # 日志清理间隔，1天

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
    
    # 检查是否需要清理日志
    log_retention_days = config_values.get('log_retention_days', 30)
    if log_retention_days > 0 and (current_time - last_times['log_clean']).total_seconds() > LOG_CLEAN_INTERVAL:
        logger_to_use.debug(f"执行额外的日志清理，保留 {log_retention_days} 天")
        # 传递保留天数和日志目录参数
        clean_old_logs(retention_days=log_retention_days, log_directory=log_dir_to_use)
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
    
    # 初始化API实例
    api = existing_api or create_api_instance(config_values, logger_to_use)
    if not api:
        logger_to_use.error("无法创建API实例，监控终止")
        return False
    
    # 初始化时间记录
    last_times = {
        'query': datetime.now() - timedelta(seconds=config_values.get('query_interval', 60)),
        'log_clean': datetime.now(),
        # 移除配置重新加载的时间记录
    }
    
    logger_to_use.info("开始API监控模式")
    
    try:
        while True:
            current_time = datetime.now()
            
            # 移除检查是否需要重新加载配置的代码块
            
            # 检查是否需要查询新日志
            if (current_time - last_times['query']).total_seconds() > config_values.get('query_interval', 60):
                process_attack_logs(api, config_values, logger_to_use)
                last_times['query'] = current_time
            
            # 每天清理一次旧日志
            if current_time.day != last_times['log_clean'].day:
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

def parse_arguments():
    """解析命令行参数"""
    import argparse
    
    # 创建参数解析器
    parser = argparse.ArgumentParser(description='SafeLine AutoBlocker - 自动监控雷池WAF攻击日志并封禁攻击IP')
    
    # 添加子命令
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # 查看配置命令
    view_parser = subparsers.add_parser('view', help='查看当前配置')
    view_parser.add_argument('--section', help='指定要查看的配置部分')
    view_parser.add_argument('--option', help='指定要查看的配置选项')
    
    # 设置配置命令
    set_parser = subparsers.add_parser('set', help='设置配置选项')
    set_parser.add_argument('section', help='配置部分名称')
    set_parser.add_argument('option', help='配置选项名称')
    set_parser.add_argument('value', help='配置选项值')
    
    # 重置配置命令
    reset_parser = subparsers.add_parser('reset', help='重置为默认配置')
    reset_parser.add_argument('--confirm', action='store_true', help='确认重置')
    
    # 重新加载配置命令
    reload_parser = subparsers.add_parser('reload', help='重新加载配置文件')
    
    # 添加其他命令行参数
    parser.add_argument('--list-attack-types', action='store_true', help='获取并显示雷池WAF支持的攻击类型')
    parser.add_argument('--get-logs', help='获取特定攻击类型的日志，多个ID用逗号分隔')
    parser.add_argument('--clean-logs', action='store_true', help='立即清理过期日志文件')
    parser.add_argument('--version', action='version', version=f'SafeLine AutoBlocker v{VERSION}')
    
    return parser.parse_args()

def main():
    """主函数"""
    # 解析命令行参数
    args = parse_arguments()
    
    # 如果是配置命令，执行配置操作并退出
    if args.command:
        return handle_config_command(args)
    
    # 正常运行程序的逻辑
    # 使用全局logger，避免重复初始化
    global logger, log_dir
    
    # 直接使用CONFIG_FILE而不是get_effective_config_file()
    config = parse_config(CONFIG_FILE)
    if not config:
        logger.error("无法加载配置，程序退出")
        return 1
    
    # 验证配置
    if not validate_config(config, logger):
        logger.error("配置验证失败，程序退出")
        return 1
    
    # 获取配置值（只解析一次配置）
    config_values = get_config_values(config)
    
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

def handle_config_command(args):
    """处理配置相关命令"""
    from config import parse_config, update_config, create_default_config, reload_config
    
    # 直接使用CONFIG_FILE而不是get_effective_config_file()
    config_file = CONFIG_FILE
    
    # 处理查看配置命令
    if args.command == 'view':
        # 查看配置
        config = parse_config(config_file)
        if not config:
            print(f"错误: 无法读取配置文件 {config_file}")
            return 1
        
        if args.section and args.option:
            # 查看特定选项
            if args.section in config and args.option in config[args.section]:
                print(f"{args.section}.{args.option} = {config[args.section][args.option]}")
            else:
                print(f"错误: 配置项 {args.section}.{args.option} 不存在")
                return 1
        elif args.section:
            # 查看特定部分
            if args.section in config:
                print(f"[{args.section}]")
                for option, value in config[args.section].items():
                    print(f"{option} = {value}")
            else:
                print(f"错误: 配置部分 {args.section} 不存在")
                return 1
        else:
            # 查看全部配置
            for section in config.sections():
                print(f"[{section}]")
                for option, value in config[section].items():
                    print(f"{option} = {value}")
                print()
            
            # 显示DEFAULT部分
            print("[DEFAULT]")
            for option, value in config.defaults().items():
                print(f"{option} = {value}")
    
    # 处理设置配置命令
    elif args.command == 'set':
        # 设置配置
        update_result = update_config({args.section: {args.option: args.value}}, config_file)
        if update_result:
            print(f"成功: 已设置 {args.section}.{args.option} = {args.value}")
        else:
            print(f"错误: 设置 {args.section}.{args.option} 失败")
            return 1
    
    # 处理重置配置命令
    elif args.command == 'reset':
        # 重置配置
        if not args.confirm:
            print("警告: 此操作将重置所有配置为默认值。如果确认，请添加 --confirm 参数。")
            return 1
        
        reset_result = create_default_config(config_file)
        if reset_result:
            print("成功: 配置已重置为默认值")
        else:
            print("错误: 重置配置失败")
            return 1
    
    # 处理重新加载配置命令
    elif args.command == 'reload':
        print(f"正在重新加载配置文件: {config_file}")
        new_config = reload_config(config_file)
        if new_config:
            print("配置文件已成功重新加载")
            return 0
        else:
            print("重新加载配置文件失败，请检查日志获取详细信息")
            return 1
    
    return 0

# 修改入口点
if __name__ == "__main__":
    sys.exit(main())
