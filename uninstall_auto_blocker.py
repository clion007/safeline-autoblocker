#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import requests

def print_banner():
    """打印欢迎信息"""
    print("=" * 60)
    print("SafeLine Auto Blocker 卸载程序")
    print("=" * 60)
    print("本程序将卸载雷池WAF自动封禁工具")
    print("=" * 60)

def stop_service():
    """停止服务"""
    print("\n正在停止服务...")
    
    try:
        subprocess.check_call(["systemctl", "stop", "safeline_auto_blocker"])
        print("✓ 已停止服务")
        
        subprocess.check_call(["systemctl", "disable", "safeline_auto_blocker"])
        print("✓ 已禁用服务开机自启")
    except subprocess.CalledProcessError as e:
        print(f"✗ 停止服务失败: {str(e)}")

def remove_service_file():
    """删除服务文件"""
    print("\n正在删除服务文件...")
    
    service_file = "/etc/systemd/system/safeline_auto_blocker.service"
    
    if os.path.exists(service_file):
        os.remove(service_file)
        print(f"✓ 已删除服务文件: {service_file}")
    else:
        print(f"✓ 服务文件不存在: {service_file}")
    
    try:
        subprocess.check_call(["systemctl", "daemon-reload"])
        print("✓ 已重新加载systemd配置")
    except subprocess.CalledProcessError as e:
        print(f"✗ 重新加载systemd配置失败: {str(e)}")

def remove_files():
    """删除文件"""
    print("\n正在删除文件...")
    
    files = [
        "/opt/safeline/scripts/safeline_auto_blocker.py",
        "/etc/safeline/auto_blocker.conf",
        "/etc/safeline/auto_blocker.key"
    ]
    
    for file in files:
        if os.path.exists(file):
            os.remove(file)
            print(f"✓ 已删除文件: {file}")
        else:
            print(f"✓ 文件不存在: {file}")

def clean_log_files():
    """清理日志文件"""
    print("\n是否清理日志文件?")
    response = input("清理日志文件? (y/n): ").strip().lower()
    
    if response != 'y':
        print("✓ 跳过日志文件清理")
        return
    
    print("\n正在清理日志文件...")
    
    log_dir = "/var/log/safeline"
    log_files = [
        os.path.join(log_dir, "auto_blocker.log"),
        os.path.join(log_dir, "security.log")
    ]
    
    for file in log_files:
        if os.path.exists(file):
            os.remove(file)
            print(f"✓ 已删除日志文件: {file}")
        else:
            print(f"✓ 日志文件不存在: {file}")
    
    # 检查日志目录是否为空，如果为空则询问是否删除
    if os.path.exists(log_dir) and len(os.listdir(log_dir)) == 0:
        response = input(f"日志目录 {log_dir} 为空，是否删除? (y/n): ").strip().lower()
        if response == 'y':
            try:
                os.rmdir(log_dir)
                print(f"✓ 已删除空日志目录: {log_dir}")
            except OSError as e:
                print(f"✗ 删除日志目录失败: {str(e)}")

def confirm_uninstall():
    """确认卸载"""
    print("\n警告: 此操作将删除所有SafeLine Auto Blocker相关文件和配置")
    response = input("确认卸载? (y/n): ").strip().lower()
    
    if response != 'y':
        print("卸载已取消")
        sys.exit(0)

def download_file(url, target_path):
    """下载文件"""
    # 使用gitmirror加速镜像
    mirror_url = url.replace("https://raw.githubusercontent.com", "https://raw.gitmirror.com")
    
    try:
        # 首先尝试从镜像下载
        response = requests.get(mirror_url, verify=False, timeout=30)
        if response.status_code != 200:
            print(f"从镜像下载失败，尝试使用原始链接...")
            response = requests.get(url, verify=False, timeout=30)
        
        if response.status_code == 200:
            with open(target_path, 'w') as f:
                f.write(response.text)
            return True
        else:
            print(f"✗ 下载失败: HTTP {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ 下载异常: {str(e)}")
        return False

def main():
    """主函数"""
    # 检查是否以root权限运行
    if os.geteuid() != 0:
        print("错误: 请使用root权限运行此脚本")
        print("提示: sudo python3 uninstall_auto_blocker.py")
        sys.exit(1)
    
    print_banner()
    confirm_uninstall()
    stop_service()
    remove_service_file()
    remove_files()
    clean_log_files()  # 添加日志文件清理
    
    print("\n" + "=" * 60)
    print("SafeLine Auto Blocker 卸载完成!")
    print("=" * 60)

if __name__ == "__main__":
    main()