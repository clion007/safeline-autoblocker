#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SafeLine Auto Blocker 卸载脚本
------------------------------
用于卸载SafeLine Auto Blocker。

作者: Clion Nieh
版本: 1.2.0
日期: 2025.4.6
许可证: MIT
"""

import os
import sys
import shutil

def print_banner():
    """打印横幅"""
    print("""
    ╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║       SafeLine Auto Blocker 卸载程序          ║
    ║                                               ║
    ║       版本: 1.2.0                             ║
    ║       作者: Clion Nieh                        ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝
    """)

def stop_service():
    """停止服务"""
    print("停止服务...")
    os.system('systemctl stop safeline_auto_blocker')
    os.system('systemctl disable safeline_auto_blocker')
    return True

def remove_service_file():
    """删除服务文件"""
    service_file = '/etc/systemd/system/safeline_auto_blocker.service'
    
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

def remove_config_files():
    """删除配置文件"""
    config_file = '/etc/safeline/auto_blocker.conf'
    key_file = '/etc/safeline/auto_blocker.key'
    example_file = '/etc/safeline/auto_blocker.conf.example'
    
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
    
    return files_removed

def remove_logs():
    """删除日志文件"""
    log_dir = '/var/log/safeline'
    
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

def remove_script():
    """删除脚本文件"""
    script_file = '/opt/safeline/scripts/safeline_auto_blocker.py'
    uninstall_script = '/opt/safeline/scripts/uninstall_auto_blocker.py'
    
    files_removed = True
    
    if os.path.exists(script_file):
        try:
            os.remove(script_file)
            print(f"删除脚本文件: {script_file}")
        except Exception as e:
            print(f"删除脚本文件失败: {str(e)}")
            files_removed = False
    else:
        print(f"脚本文件不存在: {script_file}")
    
    # 删除卸载脚本自身
    if os.path.exists(uninstall_script) and uninstall_script != __file__:
        try:
            os.remove(uninstall_script)
            print(f"删除卸载脚本: {uninstall_script}")
        except Exception as e:
            print(f"删除卸载脚本失败: {str(e)}")
            files_removed = False
    
    return files_removed

def remove_directories():
    """删除相关目录"""
    # 需要删除的目录列表
    directories = [
        '/opt/safeline/scripts',
        '/var/log/safeline',
        '/opt/safeline',
        '/etc/safeline'
    ]
    
    all_removed = True
    
    for directory in directories:
        if os.path.exists(directory):
            try:
                # 检查目录是否为空
                if not os.listdir(directory):
                    os.rmdir(directory)
                    print(f"删除空目录: {directory}")
                else:
                    print(f"目录不为空，跳过删除: {directory}")
                    all_removed = False
            except Exception as e:
                print(f"删除目录失败: {directory}, 错误: {str(e)}")
                all_removed = False
    
    return all_removed

def main():
    """主函数"""
    # 打印横幅
    print_banner()
    
    # 检查是否为root用户
    if os.geteuid() != 0:
        print("错误: 请使用root权限运行此脚本")
        return
    
    # 确认卸载
    confirm = input("确定要卸载 SafeLine Auto Blocker? (y/n): ").strip().lower()
    if confirm != 'y':
        print("卸载已取消")
        return
    
    # 停止服务
    stop_service()
    
    # 删除服务文件
    service_removed = remove_service_file()
    
    # 删除配置文件
    config_removed = remove_config_files()
    
    # 删除脚本文件
    script_removed = remove_script()
    
    # 直接删除日志
    logs_removed = remove_logs()
    
    # 删除相关目录
    dirs_removed = remove_directories()
        
    # 卸载结果反馈
    print("\n卸载结果:")
    print(f"服务文件: {'已删除' if service_removed else '删除失败'}")
    print(f"配置文件: {'已删除' if config_removed else '删除失败'}")
    print(f"脚本文件: {'已删除' if script_removed else '删除失败'}")
    print(f"日志文件: {'已删除' if logs_removed else '删除失败'}")
    print(f"相关目录: {'已清理' if dirs_removed else '部分目录未清理'}")
    
    if service_removed and config_removed and script_removed and logs_removed:
        print("\n卸载完成！所有组件已成功删除。")
    else:
        print("\n卸载完成，但部分组件删除失败，请检查上述信息。")

if __name__ == '__main__':
    main()