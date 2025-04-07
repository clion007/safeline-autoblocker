#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SafeLine AutoBlocker 卸载脚本
----------------------------
用于卸载 SafeLine AutoBlocker

作者: Clion Nieh
版本: 1.2.0
日期: 2025.4.6
许可证: MIT
"""

import os
import sys
import time
import shutil

def print_banner():
    """打印横幅"""
    print("""
    ╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║       SafeLine AutoBlocker 卸载程序           ║
    ║                                               ║
    ║       版本: 1.2.0                             ║
    ║       作者: Clion Nieh                        ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝
    """)

# 导入配置模块中的路径定义
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from config import PATHS
except ImportError:
    # 如果无法导入，创建一个临时的PATHS字典
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    INSTALL_DIR = '/opt/safeline/scripts'
    CONFIG_DIR = '/etc/safeline'
    INSTALL_LOG_DIR = '/var/log/safeline'
    SERVICE_FILE = '/etc/systemd/system/safeline-autoblocker.service'
    
    PATHS = {
        'INSTALL_DIR': INSTALL_DIR,
        'CONFIG_DIR': CONFIG_DIR,
        'INSTALL_LOG_DIR': INSTALL_LOG_DIR,
        'SERVICE_FILE': SERVICE_FILE,
        'INSTALL_CONFIG_FILE': os.path.join(CONFIG_DIR, 'safeline-autoblocker.conf'),
        'INSTALL_KEY_FILE': os.path.join(CONFIG_DIR, 'safeline-autoblocker.key'),
        'INSTALL_CONFIG_EXAMPLE': os.path.join(CONFIG_DIR, 'safeline-autoblocker.conf.example'),
        'SCRIPT_FILES': [
            os.path.join(INSTALL_DIR, 'safeline-autoblocker.py'),
            os.path.join(INSTALL_DIR, 'api.py'),
            os.path.join(INSTALL_DIR, 'config.py'),
            os.path.join(INSTALL_DIR, 'logger.py'),
            os.path.join(INSTALL_DIR, 'uninstall-autoblocker.py')
        ]
    }

def check_service_exists():
    """检查服务是否存在"""
    status = os.system('systemctl list-unit-files | grep -q safeline-autoblocker.service')
    return status == 0

def check_service_running():
    """检查服务是否正在运行"""
    status = os.system('systemctl is-active --quiet safeline-autoblocker')
    return status == 0

def stop_service():
    """停止服务（增加重试机制）"""
    # 先检查服务是否存在
    if not check_service_exists():
        print("服务不存在，跳过停止服务步骤")
        return True
    
    # 检查服务是否在运行
    if not check_service_running():
        print("服务已经停止，跳过停止服务步骤")
        return True
    
    max_retries = 3
    for attempt in range(max_retries):
        print(f"停止服务尝试 ({attempt + 1}/{max_retries})...")
        os.system('systemctl stop safeline-autoblocker')
        os.system('systemctl disable safeline-autoblocker')
        
        # 验证服务状态
        if not check_service_running():
            print("服务已成功停止")
            return True
        time.sleep(2)
    
    print("警告: 无法完全停止服务，将尝试强制删除相关文件")
    # 即使服务停止失败，也返回True以继续卸载流程
    return True

def remove_service_file():
    """删除服务文件"""
    service_file = PATHS['SERVICE_FILE']
    
    if os.path.exists(service_file):
        try:
            os.remove(service_file)
            print(f"删除服务文件: {service_file}")
            os.system('systemctl daemon-reload')
            return True
        except Exception as e:
            print(f"删除服务文件失败: {str(e)}")
            return False
    else:
        print(f"服务文件不存在: {service_file}")
        return True

def remove_config():
    """删除配置文件（增加隐藏文件清理）"""
    # 不再从config模块导入PATHS，直接使用已加载的PATHS
    config_file = PATHS['INSTALL_CONFIG_FILE']
    key_file = PATHS['INSTALL_KEY_FILE']
    example_file = PATHS['INSTALL_CONFIG_EXAMPLE']
    
    files_removed = True
    
    if os.path.exists(config_file):
        try:
            os.remove(config_file)
            print(f"删除配置文件: {config_file}")
        except Exception as e:
            print(f"删除配置文件失败: {str(e)}")
            files_removed = False
    
    if os.path.exists(key_file):
        try:
            os.remove(key_file)
            print(f"删除密钥文件: {key_file}")
        except Exception as e:
            print(f"删除密钥文件失败: {str(e)}")
            files_removed = False
    
    # 删除配置示例文件
    if os.path.exists(example_file):
        try:
            os.remove(example_file)
            print(f"删除配置示例文件: {example_file}")
        except Exception as e:
            print(f"删除配置示例文件失败: {str(e)}")
            files_removed = False
    
    # 新增隐藏文件清理
    hidden_files = [
        os.path.join(PATHS['CONFIG_DIR'], '.safeline-autoblocker'),
        os.path.join(PATHS['INSTALL_DIR'], '.safeline-cache')
    ]
    
    for h_file in hidden_files:
        if os.path.exists(h_file):
            try:
                os.remove(h_file)
                print(f"删除隐藏文件: {h_file}")
            except Exception as e:
                print(f"删除隐藏文件失败: {h_file}, 错误: {str(e)}")
                files_removed = False
    
    return files_removed

def remove_logs():
    """删除日志文件"""
    log_dir = PATHS['INSTALL_LOG_DIR']
    
    if os.path.exists(log_dir):
        try:
            shutil.rmtree(log_dir)
            print(f"删除日志目录: {log_dir}")
            return True
        except Exception as e:
            print(f"删除日志目录失败: {str(e)}")
            return False
    else:
        print(f"日志目录不存在: {log_dir}")
        return True

def remove_directories():
    """删除相关目录"""
    # 需要删除的目录列表
    directories = [
        PATHS['INSTALL_DIR'],
        PATHS['INSTALL_LOG_DIR'],
        PATHS['CONFIG_DIR'],
        os.path.dirname(PATHS['INSTALL_DIR']),  # /opt/safeline
        os.path.dirname(PATHS['INSTALL_LOG_DIR'])  # /var/log/safeline
    ]
    
    # 去重处理
    unique_dirs = list({d for d in directories if d.strip()})
    
    all_removed = True
    time.sleep(1)
    
    for directory in unique_dirs:
        if os.path.exists(directory):
            try:
                # 增加异常处理细节
                shutil.rmtree(directory, ignore_errors=True)
                print(f"成功删除目录: {directory}")
            except Exception as e:
                print(f"删除目录失败: {directory}, 错误详情: {str(e)}")
                all_removed = False
        else:
            print(f"目录不存在: {directory}")
    
    return all_removed

def remove_script():
    """删除脚本文件"""
    script_files = PATHS['SCRIPT_FILES']
    current_script = os.path.abspath(__file__)
    
    files_removed = True
    
    for script_file in script_files:
        # 跳过当前正在执行的卸载脚本
        if os.path.exists(script_file) and os.path.abspath(script_file) != current_script:
            try:
                os.remove(script_file)
                print(f"删除脚本文件: {script_file}")
            except Exception as error:
                print(f"删除脚本文件失败: {script_file}, 错误: {str(error)}")
                files_removed = False
    
    return files_removed

def main():
    """主函数"""
    # 打印横幅
    print_banner()
    
    # 检查是否为root用户
    if os.geteuid() != 0:
        print("错误: 请使用root权限运行此脚本")
        return
    
    # 确认卸载
    confirm = input("确定要卸载 SafeLine AutoBlocker? (y/n): ").strip().lower()
    if confirm != 'y':
        print("卸载已取消")
        return
    
    print("\n开始卸载过程...")
    
    # 停止服务
    service_stopped = stop_service()
    if not service_stopped:
        force_continue = input("服务停止失败，是否继续卸载? (y/n): ").strip().lower()
        if force_continue != 'y':
            print("卸载已取消")
            return
    
    # 删除服务文件
    service_removed = remove_service_file()
    
    # 删除配置文件
    config_removed = remove_config()
    
    # 删除脚本文件
    script_removed = remove_script()
    
    # 直接删除日志
    logs_removed = remove_logs()
    
    # 最后删除相关目录
    dirs_removed = remove_directories()
    
    # 卸载结果反馈
    print("\n卸载结果:")
    print(f"服务停止: {'成功' if service_stopped else '失败但继续'}")
    print(f"服务文件: {'已删除' if service_removed else '删除失败'}")
    print(f"配置文件: {'已删除' if config_removed else '删除失败'}")
    print(f"脚本文件: {'已删除' if script_removed else '删除失败'}")
    print(f"日志文件: {'已删除' if logs_removed else '删除失败'}")
    print(f"相关目录: {'已清理' if dirs_removed else '部分目录未清理'}")
    
    if service_removed and config_removed and script_removed and logs_removed and dirs_removed:
        print("\n✓ 卸载完成！所有组件已成功删除。")
    else:
        print("\n⚠ 卸载完成，但部分组件删除失败，请检查上述信息。")

if __name__ == '__main__':
    main()