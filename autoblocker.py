#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SafeLine AutoBlocker
--------------------
自动监控雷池WAF攻击日志并封禁攻击IP。

作者: Clion Nieh
版本: 1.3.0
日期: 2025.4.13
许可证: MIT
"""

import os
import sys
import time
import atexit
from factory import Factory
from datetime import datetime, timedelta
from version import PROGRAM_NAME, get_version_string


def perform_log_maintenance(current_time, last_times, configer, api, logger_instance=None):
    """集中处理日志维护任务"""    
    logger = logger_instance or Factory.get_logger()
    
    # 检查是否需要清理缓存
    if (current_time - last_times['cache_clean']).total_seconds() > int(configer.get_value('MAINTENANCE', 'CACHE_CLEAN_INTERVAL')):
        logger.debug("执行缓存清理")
        api.clean_cache()
        last_times['cache_clean'] = current_time
    
    # 检查是否需要清理日志
    logger_manager = Factory.get_logger_manager()
    log_retention_days = int(logger_manager.get_config("retention_days"))
    log_clean_interval = int(logger_manager.get_config("clean_interval"))
    
    if log_retention_days > 0 and (current_time - last_times['log_clean']).total_seconds() > log_clean_interval:
        logger.debug(f"执行日志清理，保留 {log_retention_days} 天")
        logger_manager.clean_old_logs()
        last_times['log_clean'] = current_time
    
    return last_times

def api_monitor(configer=None, logger_instance=None, existing_api=None):
    """API监控函数"""
    configer = configer or Factory.get_configer()
    logger = logger_instance or Factory.get_logger()
    
    # 初始化API实例 - 使用工厂模式
    api = existing_api or Factory.get_api_client()
    if not api:
        logger.error("无法创建API实例，监控终止")
        return False
    
    # 初始化时间记录
    last_times = {
        'query': datetime.now() - timedelta(seconds=int(configer.get_value('GENERAL', 'QUERY_INTERVAL'))),
        'log_clean': datetime.now(),
        'cache_clean': datetime.now()
    }
    
    logger.info("开始API监控模式")
    
    try:
        while True:
            current_time = datetime.now()
            
            # 检查是否需要查询新日志
            if (current_time - last_times['query']).total_seconds() > int(configer.get_value('GENERAL', 'QUERY_INTERVAL')):
                # 直接调用API类中的方法处理攻击日志
                processed_count = api.process_attack_logs()
                if processed_count > 0:
                    logger.info(f"处理了 {processed_count} 条攻击日志")
                last_times['query'] = current_time
            
            # 每天清理一次旧日志
            if current_time.day != last_times['log_clean'].day:
                last_times = perform_log_maintenance(current_time, last_times, configer, api, logger)
            
            time.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("收到中断信号，正在优雅退出...")
        # 执行清理工作
        api.clean_cache()
        logger.info("监控已停止")
    except Exception as error:
        logger.error(f"监控过程中发生错误: {str(error)}")
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
    
    # 版本信息命令
    version_parser = subparsers.add_parser('version', help='显示版本信息')
    
    # 日志命令组
    log_parser = subparsers.add_parser('log', help='日志相关操作')
    log_subparsers = log_parser.add_subparsers(dest='log_command', help='日志操作类型')
    
    # 设置日志级别
    log_level_parser = log_subparsers.add_parser('level', help='设置日志级别')
    log_level_parser.add_argument('value', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='日志级别')
    
    # 设置日志保留天数
    log_retention_parser = log_subparsers.add_parser('retention', help='设置日志保留天数')
    log_retention_parser.add_argument('days', type=int, help='保留天数')
    
    # 清理日志
    log_clean_parser = log_subparsers.add_parser('clean', help='清理过期日志文件')
    
    # IP组配置命令
    ip_group_parser = subparsers.add_parser('ip-group', help='IP组相关配置')
    ip_group_subparsers = ip_group_parser.add_subparsers(dest='ip_group_command', help='IP组操作类型')
    
    # 设置高危IP组
    high_risk_parser = ip_group_subparsers.add_parser('high-risk', help='设置高危IP组名称')
    high_risk_parser.add_argument('name', help='高危IP组名称')
    
    # 设置低危IP组
    low_risk_parser = ip_group_subparsers.add_parser('low-risk', help='设置低危IP组名称')
    low_risk_parser.add_argument('name', help='低危IP组名称')
    
    # 配置攻击类型与IP组的映射
    map_parser = ip_group_subparsers.add_parser('map', help='配置攻击类型与IP组的映射')
    map_parser.add_argument('attack_type', help='攻击类型ID')
    map_parser.add_argument('risk_level', choices=['high', 'low'], help='风险等级(high/low)')
    
    return parser.parse_args()

def create_pid_file():
    """创建PID文件"""
    pid_file = '/var/run/safeline-autoblocker.pid'
    
    try:
        if os.path.exists(pid_file):
            try:
                with open(pid_file, 'r') as f:
                    old_pid = int(f.read().strip())
                try:
                    os.kill(old_pid, 0)
                    raise RuntimeError(f"程序已在运行中 (PID: {old_pid})")
                except (ProcessLookupError, ValueError):
                    os.remove(pid_file)
            except (IOError, ValueError):
                # PID文件损坏，直接删除
                os.remove(pid_file)
        
        # 写入当前进程PID
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
        
        # 设置适当的权限
        os.chmod(pid_file, 0o644)
        
        # 注册退出时的清理函数
        atexit.register(lambda: os.remove(pid_file) if os.path.exists(pid_file) else None)
        
    except PermissionError:
        raise RuntimeError("无法创建PID文件，请确保有足够的权限")
    except (IOError, OSError) as e:
        raise RuntimeError(f"无法创建或管理PID文件: {str(e)}")

def main():
    """主函数"""
    try:
        # 获取配置管理器并加载配置
        configer = Factory.get_configer()
        if not configer.load():
            return 1
        
        # 解析命令行参数
        args = parse_arguments()
        
        # 获取日志记录器
        logger = Factory.get_logger()
        
        # 处理命令
        if args.command == 'version':
            print(get_version_string())
            return 0
        elif args.command == 'ip-group':
            if args.ip_group_command == 'high-risk':
                return handle_config_command(argparse.Namespace(
                    command='set',
                    section='IP_GROUPS',
                    option='HIGH_RISK',
                    value=args.name
                ), configer, logger)
            elif args.ip_group_command == 'low-risk':
                return handle_config_command(argparse.Namespace(
                    command='set',
                    section='IP_GROUPS',
                    option='LOW_RISK',
                    value=args.name
                ), configer, logger)
            elif args.ip_group_command == 'map':
                group_type = 'HIGH_RISK' if args.risk_level == 'high' else 'LOW_RISK'
                group_name = configer.get_value('IP_GROUPS', group_type)
                if not group_name:
                    logger.error(f"错误: 未设置{group_type}组名称")
                    return 1
                return handle_config_command(argparse.Namespace(
                    command='set',
                    section='TYPE_GROUP_MAPPING',
                    option=args.attack_type,
                    value=group_name
                ), configer, logger)
            return 0
        elif args.command == 'log':
            if args.log_command == 'level':
                configer.set_log_config('log_level', args.value)
                Factory.get_logger_manager().reload()
                logger.info(f"已设置日志级别为: {args.value}")
            elif args.log_command == 'retention':
                configer.set_log_config('retention_days', args.days)
                Factory.get_logger_manager().reload()
                logger.info(f"已设置日志保留天数为: {args.days} 天")
            elif args.log_command == 'clean':
                logger_manager = Factory.get_logger_manager()
                log_retention_days = logger_manager.get_config("retention_days")
                logger.info(f"手动清理日志，保留 {log_retention_days} 天")
                logger_manager.clean_old_logs()
                return 0
        elif args.command in ['view', 'set', 'reset', 'reload']:
            return handle_config_command(args, configer, logger)
        
        # 如果没有指定命令，进入API监控模式
        try:
            # 创建PID文件（仅在监控模式下）
            create_pid_file()
            
            api = Factory.get_api_client()
            if not api:
                logger.error("无法创建API实例，操作取消")
                return 1
            
            # 进入API监控模式
            result = api_monitor(configer, logger, api)
            if not result:
                logger.error("API监控模式异常退出")
                return 1
            return 0
            
        except RuntimeError as e:
            logger.error(f"启动监控失败: {str(e)}")
            return 1
            
    except Exception as e:
        logger = Factory.get_logger()
        logger.error(f"程序启动失败: {str(e)}")
        return 1

def handle_config_command(args, configer, logger=None):
    """处理配置相关命令"""
    logger = logger or Factory.get_logger()
    
    if args.command == 'view':
        if not configer.is_loaded():  # 使用方法检查配置状态
            logger.error("错误: 配置未加载")
            return 1
            
        if args.section and args.option:
            value = configer.get_value(args.section, args.option)
            if value is not None:
                print(f"{args.section}.{args.option} = {value}")
            else:
                logger.error(f"错误: 配置项 {args.section}.{args.option} 不存在")
                return 1
        elif args.section:
            section_data = configer.get_section(args.section)
            if section_data:
                print(f"[{args.section}]")
                for option, value in section_data.items():
                    print(f"{option} = {value}")
            else:
                logger.error(f"错误: 配置部分 {args.section} 不存在")
                return 1
        else:
            configer.print_config()  # 使用配置管理器的方法
    
    elif args.command == 'set':
        if configer.set_value(args.section, args.option, args.value):
            logger.info(f"成功: 已设置 {args.section}.{args.option} = {args.value}")
        else:
            logger.error(f"错误: 设置 {args.section}.{args.option} 失败")
            return 1
    
    elif args.command == 'reset':
        if not args.confirm:
            logger.warning("警告: 此操作将重置所有配置为默认值。如果确认，请添加 --confirm 参数。")
            return 1
        
        if configer.reset():  # 修改方法名
            logger.info("成功: 配置已重置为默认值")
        else:
            logger.error("错误: 重置配置失败")
            return 1
    
    elif args.command == 'reload':
        if configer.reload():  # 添加重新加载方法
            logger.info("成功: 配置已重新加载")
        else:
            logger.error("错误: 重新加载配置失败")
            return 1
    
    return 0

# 修改入口点
if __name__ == "__main__":
    sys.exit(main())
