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
    
    return files_removed

def remove_script():
    """删除脚本文件"""
    script_file = '/opt/safeline/scripts/safeline_auto_blocker.py'
    
    if os.path.exists(script_file):
        try:
            os.remove(script_file)
            print(f"删除脚本文件: {script_file}")
            return True
        except Exception as e:
            print(f"删除脚本文件失败: {str(e)}")
            return False
    else:
        print(f"脚本文件不存在: {script_file}")
        return True

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
    remove_service_file()
    
    # 删除配置文件
    remove_config_files()
    
    # 删除脚本文件
    remove_script()
    
    print("\n卸载完成！")

if __name__ == '__main__':
    main()