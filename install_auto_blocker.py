#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SafeLine Auto Blocker 安装脚本
------------------------------
用于安装和配置SafeLine Auto Blocker。

作者: Clion Nieh
版本: 1.2.0
日期: 2025.4.6
许可证: MIT
"""

import os
import sys
import argparse
import configparser
import getpass
import urllib.request
import shutil
from cryptography.fernet import Fernet

def print_banner():
    """打印横幅"""
    print("""
    ╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║       SafeLine Auto Blocker 安装程序          ║
    ║                                               ║
    ║       版本: 1.2.0                             ║
    ║       作者: Clion Nieh                        ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝
    """)

def check_dependencies():
    """检查依赖"""
    try:
        import requests
        from cryptography.fernet import Fernet
        return True
    except ImportError as e:
        print(f"缺少依赖: {str(e)}")
        print("请安装所需依赖: pip3 install requests cryptography")
        return False

def create_directories():
    """创建必要的目录"""
    directories = [
        '/opt/safeline/scripts',
        '/etc/safeline',
        '/var/log/safeline'
    ]
    
    for directory in directories:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                print(f"创建目录: {directory}")
            except Exception as e:
                print(f"创建目录 {directory} 失败: {str(e)}")
                return False
    
    return True

def copy_script():
    """复制脚本文件"""
    source = 'safeline_auto_blocker.py'
    destination = '/opt/safeline/scripts/safeline_auto_blocker.py'
    
    if not os.path.exists(source):
        print(f"脚本文件不存在: {source}")
        return False
    
    try:
        shutil.copy2(source, destination)
        os.chmod(destination, 0o755)  # 添加执行权限
        print(f"复制脚本文件到: {destination}")
        return True
    except Exception as e:
        print(f"复制脚本文件失败: {str(e)}")
        return False

def generate_key():
    """生成加密密钥"""
    key_file = '/etc/safeline/auto_blocker.key'
    
    try:
        key = Fernet.generate_key().decode()
        with open(key_file, 'w') as f:
            f.write(key)
        os.chmod(key_file, 0o600)  # 设置权限为只有所有者可读写
        print(f"生成加密密钥: {key_file}")
        return key
    except Exception as e:
        print(f"生成加密密钥失败: {str(e)}")
        return None

# 在create_config函数中添加日志保留天数的配置选项
def create_config(key):
    """创建配置文件"""
    config_file = '/etc/safeline/auto_blocker.conf'
    
    # 获取用户输入
    print("\n请输入以下配置信息:")
    host = input("雷池API地址 [localhost]: ").strip() or 'localhost'
    port = input("雷池API端口 [9443]: ").strip() or '9443'
    token = getpass.getpass("雷池API令牌: ").strip()
    default_ip_group = input("默认IP组名称 [人机验证]: ").strip() or '人机验证'
    
    use_type_groups = input("是否为不同攻击类型配置不同IP组? (y/n) [y]: ").strip().lower() != 'n'
    
    attack_types_filter = input("攻击类型过滤（多个ID用逗号分隔，留空监控所有类型）: ").strip()
    
    query_interval = input("API查询间隔（秒）[60]: ").strip() or '60'
    max_logs = input("每次查询的最大日志数量 [100]: ").strip() or '100'
    debug_mode = input("是否启用调试模式? (y/n) [n]: ").strip().lower() == 'y'
    
    # 添加日志保留天数配置
    log_retention_days = input("日志保留天数（0表示永久保留）[30]: ").strip() or '30'
    
    # 加密令牌
    f = Fernet(key.encode())
    encrypted_token = f.encrypt(token.encode()).decode()
    
    # 创建配置
    config = configparser.ConfigParser()
    
    config['DEFAULT'] = {
        'SAFELINE_HOST': host,
        'SAFELINE_PORT': port,
        'SAFELINE_TOKEN_ENCRYPTED': encrypted_token,
        'DEFAULT_IP_GROUP': default_ip_group,
        'USE_TYPE_GROUPS': str(use_type_groups),
        'ATTACK_TYPES_FILTER': attack_types_filter,
        'QUERY_INTERVAL': query_interval,
        'MAX_LOGS_PER_QUERY': max_logs,
        'DEBUG_MODE': str(debug_mode),
        'LOG_RETENTION_DAYS': log_retention_days
    }
    
    # 添加攻击类型到IP组的映射
    config['TYPE_GROUP_MAPPING'] = {
        # 高危攻击类型加入黑名单组
        '0': '黑名单',  # SQL注入
        '5': '黑名单',  # 后门
        '7': '黑名单',  # 代码执行
        '8': '黑名单',  # 代码注入
        '9': '黑名单',  # 命令注入
        '11': '黑名单', # 文件包含
        '29': '黑名单', # 模板注入
        
        # 低危攻击类型加入人机验证组
        '1': '人机验证',  # XSS
        '2': '人机验证',  # CSRF
        '3': '人机验证',  # SSRF
        '4': '人机验证',  # 拒绝服务
        '6': '人机验证',  # 反序列化
        '10': '人机验证', # 文件上传
        '21': '人机验证'  # 扫描器
    }
    
    try:
        with open(config_file, 'w') as f:
            config.write(f)
        os.chmod(config_file, 0o600)  # 设置权限为只有所有者可读写
        print(f"创建配置文件: {config_file}")
        return True
    except Exception as e:
        print(f"创建配置文件失败: {str(e)}")
        return False

def create_service():
    """创建systemd服务"""
    service_file = '/etc/systemd/system/safeline_auto_blocker.service'
    
    service_content = """[Unit]
Description=SafeLine Auto Blocker
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/safeline/scripts/safeline_auto_blocker.py
Restart=always

[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open(service_file, 'w') as f:
            f.write(service_content)
        print(f"创建服务文件: {service_file}")
        
        # 重新加载systemd配置
        os.system('systemctl daemon-reload')
        
        # 启用服务
        os.system('systemctl enable safeline_auto_blocker')
        
        return True
    except Exception as e:
        print(f"创建服务文件失败: {str(e)}")
        return False

def download_main_script():
    """下载主监控脚本"""
    script_dir = '/opt/safeline/scripts'
    script_path = os.path.join(script_dir, 'safeline_auto_blocker.py')
    
    # 确保目录存在
    if not os.path.exists(script_dir):
        try:
            os.makedirs(script_dir, exist_ok=True)
            print(f"创建目录: {script_dir}")
        except Exception as e:
            print(f"创建目录失败: {str(e)}")
            return False
    
    # 下载脚本
    try:
        print("正在下载主监控脚本...")
        urllib.request.urlretrieve(
            'https://raw.gitmirror.com/clion007/safeline-auto-blocker/main/safeline_auto_blocker.py',
            script_path
        )
        os.chmod(script_path, 0o755)  # 添加执行权限
        print(f"下载脚本文件: {script_path}")
        return True
    except Exception as e:
        print(f"下载脚本文件失败: {str(e)}")
        return False

def start_service():
    """启动服务并检查状态"""
    try:
        # 启动服务
        os.system('systemctl start safeline_auto_blocker')
        
        # 检查服务状态
        status = os.system('systemctl is-active --quiet safeline_auto_blocker')
        if status == 0:
            print("服务启动成功")
            return True
        else:
            print("服务启动失败，请检查日志获取详细信息")
            print("可使用命令: journalctl -u safeline_auto_blocker -n 50")
            return False
    except Exception as e:
        print(f"启动服务时出错: {str(e)}")
        return False

def main():
    """主函数"""
    # 打印横幅
    print_banner()
    
    # 检查操作系统类型
    if os.name == 'nt':
        print("警告: 此脚本设计用于Linux系统，在Windows上运行可能会出现问题")
        proceed = input("是否继续? (y/n) [n]: ").strip().lower() == 'y'
        if not proceed:
            print("安装已取消")
            return
    else:
        # 在Linux系统上检查root权限
        if os.geteuid() != 0:
            print("错误: 请使用root权限运行此脚本")
            return
    
    # 检查依赖
    print("检查依赖...")
    if not check_dependencies():
        print("依赖检查失败，安装终止")
        return
    
    # 下载主监控脚本
    if not download_main_script():
        print("下载主监控脚本失败，安装终止")
        return
    
    # 创建必要的目录
    if not create_directories():
        return
    
    # 生成密钥
    key = generate_key()
    if not key:
        return
    
    # 创建配置文件
    if not create_config(key):
        return
    
    # 创建服务
    if not create_service():
        return
    
    # 启动服务
    if not start_service():
        return
    
    print("\n安装完成！")
    print("您可以使用以下命令管理服务:")
    print("  启动服务: systemctl start safeline_auto_blocker")
    print("  停止服务: systemctl stop safeline_auto_blocker")
    print("  查看状态: systemctl status safeline_auto_blocker")
    print("  查看日志: journalctl -u safeline_auto_blocker -f")

if __name__ == '__main__':
    main()