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

import sys
import time
from datetime import datetime, timedelta
from version import PROGRAM_NAME, get_version_string
from factory import Factory

def perform_log_maintenance(current_time, last_times, config_manager, api, logger_instance=None, log_directory=None):
    """集中处理日志维护任务"""    
    logger_to_use = logger_instance or Factory.get_logger()
    
    # 检查是否需要清理缓存
    if (current_time - last_times['cache_clean']).total_seconds() > int(config_manager.get_value('MAINTENANCE', 'CACHE_CLEAN_INTERVAL')):
        logger_to_use.debug("执行缓存清理")
        api.clean_cache()
        last_times['cache_clean'] = current_time
    
    # 检查是否需要清理日志
    log_retention_days = int(config_manager.get_value('LOGS', 'RETENTION_DAYS'))
    if log_retention_days > 0 and (current_time - last_times['log_clean']).total_seconds() > int(config_manager.get_value('MAINTENANCE', 'LOG_CLEAN_INTERVAL')):
        logger_to_use.debug(f"执行额外的日志清理，保留 {log_retention_days} 天")
        # 修改：使用工厂模式获取日志管理器
        Factory.get_logger_manager().clean_old_logs(retention_days=log_retention_days)
        last_times['log_clean'] = current_time
    
    return last_times

def process_attack_logs(api, config_manager, logger_instance=None):
    """处理攻击日志的通用函数"""
    logger_to_use = logger_instance or Factory.get_logger()
    
    # 获取配置值
    high_risk_ip_group = config_manager.get_value('ip_groups', 'high_risk')
    low_risk_ip_group = config_manager.get_value('ip_groups', 'low_risk')
    type_group_mapping = config_manager.get_value('attack_types', 'group_mapping')
    attack_types_filter = config_manager.get_value('attack_types', 'filter')
    max_logs = config_manager.get_value('api', 'max_logs_per_query')
    
    # 获取攻击日志
    logs = api.get_attack_logs(limit=max_logs)
    
    if not logs:
        logger_to_use.debug("没有新的攻击日志")
        return 0
    
    logger_to_use.debug(f"获取到 {len(logs)} 条攻击日志")
    
    # 处理每条日志
    processed_count = 0
    for log_entry in logs:
        if process_log_entry(log_entry, api, low_risk_ip_group, high_risk_ip_group, 
                          type_group_mapping, attack_types_filter, logger_to_use):
            processed_count += 1
    
    if processed_count > 0:
        logger_to_use.info(f"处理了 {processed_count} 条攻击日志")
    
    return processed_count

def api_monitor(config_manager=None, logger_instance=None, existing_api=None):
    """API监控函数"""
    config_manager = config_manager or Factory.get_config_manager()
    if not config_manager.load():
        return False
    
    logger_to_use = logger_instance or Factory.get_logger()
    
    # 初始化API实例 - 使用工厂模式
    api = existing_api or Factory.get_api_client()
    if not api:
        logger_to_use.error("无法创建API实例，监控终止")
        return False
    
    # 初始化时间记录
    last_times = {
        'query': datetime.now() - timedelta(seconds=config_manager.get_value('api', 'query_interval')),
        'log_clean': datetime.now(),
        'cache_clean': datetime.now()
    }
    
    logger_to_use.info("开始API监控模式")
    
    try:
        while True:
            current_time = datetime.now()
            
            # 检查是否需要查询新日志
            if (current_time - last_times['query']).total_seconds() > config_manager.get_value('api', 'query_interval'):
                process_attack_logs(api, config_manager, logger_to_use)
                last_times['query'] = current_time
            
            # 每天清理一次旧日志
            if current_time.day != last_times['log_clean'].day:
                last_times = perform_log_maintenance(current_time, last_times, config_manager, api, logger_to_use)
            
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
    parser = argparse.ArgumentParser(description=f'{PROGRAM_NAME} - 自动监控雷池WAF攻击日志并封禁攻击IP')
    
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
    parser.add_argument('--version', action='version', version=get_version_string())
    
    # 添加日志相关参数
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='设置日志级别')
    
    return parser.parse_args()

def main():
    """主函数"""
    # 获取配置管理器
    config_manager = Factory.get_config_manager()
    
    # 解析命令行参数
    args = parse_arguments()
    
    # 如果指定了日志级别，更新配置
    if hasattr(args, 'log_level') and args.log_level:
        config_manager.set_value('LOGS', 'LEVEL', args.log_level)
        # 重置日志管理器，使其重新初始化
        Factory.reset()
    
    # 获取日志记录器
    logger = Factory.get_logger()
    
    # 如果是配置命令，执行配置操作并退出
    if args.command:
        return handle_config_command(args, config_manager, logger)
    
    # 清理日志
    if args.clean_logs:
        log_retention_days = config_manager.get_value('LOGS', 'RETENTION_DAYS')
        logger.info(f"手动清理日志，保留 {log_retention_days} 天")
        Factory.get_logger_manager().clean_old_logs(retention_days=log_retention_days)
        return 0
    
    # 只在需要API实例时创建
    api = None
    if not args.clean_logs:
        try:
            api = Factory.get_api_client()
            if not api:
                logger.error("无法创建API实例，操作取消")
                return 1
        except Exception as error:
            logger.error(f"无法创建API实例: {str(error)}")
            return 1
    
    # 获取攻击类型列表或日志
    if args.list_attack_types or args.get_logs:
        if api:
            if args.list_attack_types:
                attack_types = config_manager.get_value('TYPE_GROUP_MAPPING', None)
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
                            attack_type_name = api.get_attack_type_name(attack_type_int)  # 使用API实例的方法
                            print(f"\n攻击类型 {attack_type} ({attack_type_name}) 的最新日志:")
                            for log in logs:
                                print(f"IP: {log.get('src_ip')}, 时间: {log.get('time')}, URL: {log.get('website', '')}")
                        else:
                            logger.info(f"未找到攻击类型 {attack_type} 的日志")
                    except ValueError:
                        logger.error(f"无效的攻击类型ID: {attack_type}，必须是整数")
        return 0
    
    # 默认为API监控模式，直接使用已创建的API实例和日志记录器
    if api:  # 确保API实例存在
        result = api_monitor(config_manager, logger, api)
        if not result:
            logger.error("API监控模式异常退出")
            return 1
    else:
        logger.error("无法启动API监控模式：API实例未创建")
        return 1
    
    return 0

def handle_config_command(args, config_manager, logger=None):
    """处理配置相关命令"""
    logger = logger or Factory.get_logger()
    
    if args.command == 'view':
        if not config_manager.is_loaded():  # 使用方法检查配置状态
            logger.error("错误: 配置未加载")
            return 1
            
        if args.section and args.option:
            value = config_manager.get_value(args.section, args.option)
            if value is not None:
                print(f"{args.section}.{args.option} = {value}")
            else:
                logger.error(f"错误: 配置项 {args.section}.{args.option} 不存在")
                return 1
        elif args.section:
            section_data = config_manager.get_section(args.section)
            if section_data:
                print(f"[{args.section}]")
                for option, value in section_data.items():
                    print(f"{option} = {value}")
            else:
                logger.error(f"错误: 配置部分 {args.section} 不存在")
                return 1
        else:
            config_manager.print_config()  # 使用配置管理器的方法
    
    elif args.command == 'set':
        if config_manager.set_value(args.section, args.option, args.value):
            logger.info(f"成功: 已设置 {args.section}.{args.option} = {args.value}")
        else:
            logger.error(f"错误: 设置 {args.section}.{args.option} 失败")
            return 1
    
    elif args.command == 'reset':
        if not args.confirm:
            logger.warning("警告: 此操作将重置所有配置为默认值。如果确认，请添加 --confirm 参数。")
            return 1
        
        if config_manager.reset():  # 修改方法名
            logger.info("成功: 配置已重置为默认值")
        else:
            logger.error("错误: 重置配置失败")
            return 1
    
    elif args.command == 'reload':
        if config_manager.reload():  # 添加重新加载方法
            logger.info("成功: 配置已重新加载")
        else:
            logger.error("错误: 重新加载配置失败")
            return 1
    
    return 0

# 修改入口点
if __name__ == "__main__":
    sys.exit(main())
