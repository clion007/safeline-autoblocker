#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SafeLine Auto Blocker 安装脚本
----------------------------
用于安装SafeLine Auto Blocker。

作者: Clion Nieh
版本: 1.2.0
日期: 2025.4.6
许可证: MIT
"""

import os
import sys
import shutil
import urllib.request
import getpass
import time
import subprocess
from cryptography.fernet import Fernet

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
    SERVICE_FILE = '/etc/systemd/system/safeline-auto-blocker.service'
    
    PATHS = {
        'INSTALL_DIR': INSTALL_DIR,
        'CONFIG_DIR': CONFIG_DIR,
        'INSTALL_LOG_DIR': INSTALL_LOG_DIR,
        'SERVICE_FILE': SERVICE_FILE,
        'INSTALL_CONFIG_FILE': os.path.join(CONFIG_DIR, 'auto_blocker.conf'),
        'INSTALL_KEY_FILE': os.path.join(CONFIG_DIR, '.key'),
        'INSTALL_CONFIG_EXAMPLE': os.path.join(CONFIG_DIR, 'auto_blocker.conf.example'),
        'SCRIPT_FILES': [
            os.path.join(INSTALL_DIR, 'safeline_auto_blocker.py'),
            os.path.join(INSTALL_DIR, 'api.py'),
            os.path.join(INSTALL_DIR, 'config.py'),
            os.path.join(INSTALL_DIR, 'logger.py'),
            os.path.join(INSTALL_DIR, 'uninstall_auto_blocker.py')
        ]
    }
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

def create_directories(paths):
    """创建必要的目录"""
    directories = [
        paths['INSTALL_DIR'],
        paths['CONFIG_DIR'],
        paths['INSTALL_LOG_DIR']
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

# 添加下载模块文件的函数
def download_file(url, destination, max_retries=3):
    """
    通用下载函数，支持curl、wget和urllib，带重试逻辑
    """
    print(f"正在下载: {url}")
    
    # 检查是否有curl
    curl_available = shutil.which('curl') is not None
    # 检查是否有wget
    wget_available = shutil.which('wget') is not None
    
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            if curl_available:
                # 使用curl下载，带重试和超时
                result = subprocess.run(
                    ['curl', '--fail', '--silent', '--location', '--connect-timeout', '15', 
                     '--retry', '3', '--retry-delay', '2', '--output', destination, url],
                    check=True
                )
                return True
            elif wget_available:
                # 使用wget下载，带重试和超时
                result = subprocess.run(
                    ['wget', '--quiet', '--tries=3', '--timeout=15', '--retry-connrefused',
                     '--output-document', destination, url],
                    check=True
                )
                return True
            else:
                # 如果都不可用，使用Python的urllib
                urllib.request.urlretrieve(url, destination)
                return True
        except Exception as error:
            retry_count += 1
            if retry_count < max_retries:
                print(f"下载失败，正在尝试第 {retry_count} 次重试...")
                time.sleep(2)
            else:
                print(f"下载失败: {str(error)}")
                return False
    
    return False

def download_main_script(paths):
    """下载主监控脚本"""
    script_dir = paths['INSTALL_DIR']
    script_path = os.path.join(script_dir, 'safeline_auto_blocker.py')
    
    # 确保目录存在
    if not os.path.exists(script_dir):
        try:
            os.makedirs(script_dir, exist_ok=True)
            print(f"创建目录: {script_dir}")
        except Exception as error:
            print(f"创建目录失败: {str(error)}")
            return False
    
    # 下载脚本
    url = 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/safeline_auto_blocker.py'
    if download_file(url, script_path):
        os.chmod(script_path, 0o755)  # 添加执行权限
        print(f"下载脚本文件: {script_path}")
        return True
    else:
        return False

def download_module_files(paths):
    """下载模块文件"""
    module_files = [
        {
            'url': 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/api.py',
            'path': os.path.join(paths['INSTALL_DIR'], 'api.py')
        },
        {
            'url': 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/config.py',
            'path': os.path.join(paths['INSTALL_DIR'], 'config.py')
        },
        {
            'url': 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/logger.py',
            'path': os.path.join(paths['INSTALL_DIR'], 'logger.py')
        },
        {
            'url': 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/__init__.py',
            'path': os.path.join(paths['INSTALL_DIR'], '__init__.py')
        }
    ]
    
    success = True
    for file_info in module_files:
        if not download_file(file_info['url'], file_info['path']):
            success = False
    
    return success

def download_additional_files(paths):
    """下载配置示例文件和卸载脚本文件"""
    files_to_download = [
        {
            'url': 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/auto_blocker.conf.example',
            'path': paths['INSTALL_CONFIG_EXAMPLE']
        },
        {
            'url': 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/uninstall_auto_blocker.py',
            'path': os.path.join(paths['INSTALL_DIR'], 'uninstall_auto_blocker.py')
        }
    ]
    
    success = True
    for file_info in files_to_download:
        if download_file(file_info['url'], file_info['path']):
            # 为卸载脚本添加执行权限
            if file_info['path'].endswith('.py') or file_info['path'].endswith('.sh'):
                os.chmod(file_info['path'], 0o755)
        else:
            success = False
    
    return success

def copy_script(paths):
    """复制脚本文件"""
    source = 'safeline_auto_blocker.py'
    destination = os.path.join(paths['INSTALL_DIR'], 'safeline_auto_blocker.py')
    
    if not os.path.exists(source):
        print(f"脚本文件不存在: {source}")
        return False
    
    try:
        shutil.copy2(source, destination)
        os.chmod(destination, 0o755)  # 添加执行权限
        print(f"复制脚本文件到: {destination}")
        return True
    except Exception as error:
        print(f"复制脚本文件失败: {str(error)}")
        return False

def generate_key(paths):
    """生成加密密钥"""
    key_file = paths['INSTALL_KEY_FILE']
    
    try:
        key = Fernet.generate_key().decode()
        with open(key_file, 'w') as key_file_handle:  # 修改: f -> key_file_handle
            key_file_handle.write(key)
        os.chmod(key_file, 0o600)  # 设置权限为只有所有者可读写
        print(f"生成加密密钥: {key_file}")
        return key
    except Exception as error:
        print(f"生成加密密钥失败: {str(error)}")
        return None

# 在create_config函数中添加日志保留天数的配置选项
def create_config(paths, key):
    """创建配置文件"""
    # 使用安装路径中的配置文件
    config_file = paths['INSTALL_CONFIG_FILE']
    example_file = paths['INSTALL_CONFIG_EXAMPLE']
    
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

def encrypt_token(token, key):
    """加密令牌"""
    try:
        fernet = Fernet(key.encode())  # 修改: f -> fernet
        encrypted_token = fernet.encrypt(token.encode()).decode()
        return encrypted_token
    except Exception as error:
        print(f"加密令牌失败: {str(error)}")
        return None

def create_config_file(paths, token, key):
    """创建配置文件"""
    config_file = paths['INSTALL_CONFIG_FILE']
    
    # 加密令牌
    encrypted_token = encrypt_token(token, key)
    if not encrypted_token:
        return False
    
    # 创建配置文件
    try:
        with open(config_file, 'w') as config_file_handle:  # 修改: f -> config_file_handle
            config_file_handle.write(f"""[DEFAULT]
# 雷池WAF主机地址和端口
SAFELINE_HOST = localhost
SAFELINE_PORT = 9443

# 加密后的API令牌
SAFELINE_TOKEN_ENCRYPTED = {encrypted_token}

# 默认IP组名称
DEFAULT_IP_GROUP = 人机验证

# 是否使用攻击类型分组
USE_TYPE_GROUPS = true

# 查询间隔(秒)
QUERY_INTERVAL = 60

# 每次查询最大日志数量
MAX_LOGS_PER_QUERY = 100

# 调试模式
DEBUG_MODE = false

# 日志保留天数
LOG_RETENTION_DAYS = 30

# 攻击类型过滤(逗号分隔的攻击类型ID)
ATTACK_TYPES_FILTER = 

# 配置重新加载间隔(秒)
CONFIG_RELOAD_INTERVAL = 300

[TYPE_GROUP_MAPPING]
# 攻击类型到IP组的映射
# 格式: 攻击类型ID = IP组名称
# 示例:
# 1 = 黑名单
# 2 = 人机验证
""")
        
        # 设置权限
        os.chmod(config_file, 0o600)
        print(f"创建配置文件: {config_file}")
        return True
    except Exception as error:
        print(f"创建配置文件失败: {str(error)}")
        return False

def download_main_script(paths):
    """下载主监控脚本"""
    script_dir = paths['INSTALL_DIR']
    script_path = os.path.join(script_dir, 'safeline_auto_blocker.py')
    
    # 确保目录存在
    if not os.path.exists(script_dir):
        try:
            os.makedirs(script_dir, exist_ok=True)
            print(f"创建目录: {script_dir}")
        except Exception as error:
            print(f"创建目录失败: {str(error)}")
            return False
    
    # 下载脚本
    url = 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/safeline_auto_blocker.py'
    if download_file(url, script_path):
        os.chmod(script_path, 0o755)  # 添加执行权限
        print(f"下载脚本文件: {script_path}")
        return True
    else:
        return False

# 修改下载模块文件函数，使用更稳定的镜像
def download_module_files(paths):
    """下载模块文件"""
    module_files = [
        {
            'url': 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/api.py',
            'path': os.path.join(paths['INSTALL_DIR'], 'api.py')
        },
        {
            'url': 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/config.py',
            'path': os.path.join(paths['INSTALL_DIR'], 'config.py')
        },
        {
            'url': 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/logger.py',
            'path': os.path.join(paths['INSTALL_DIR'], 'logger.py')
        },
        {
            'url': 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/__init__.py',
            'path': os.path.join(paths['INSTALL_DIR'], '__init__.py')
        }
    ]
    
    success = True
    for file_info in module_files:  # 修复：使用module_files而不是files_to_download
        try:
            print(f"正在下载 {os.path.basename(file_info['path'])}...")
            urllib.request.urlretrieve(file_info['url'], file_info['path'])
            print(f"下载文件: {file_info['path']}")
        except Exception as error:
            print(f"下载文件 {file_info['path']} 失败: {str(error)}")
            success = False
    
    return success

# 修改下载附加文件函数，使用更稳定的镜像
def download_additional_files(paths):
    """下载配置示例文件和卸载脚本文件"""
    files_to_download = [
        {
            'url': 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/auto_blocker.conf.example',
            'path': paths['INSTALL_CONFIG_EXAMPLE']
        },
        {
            'url': 'https://raw.staticdn.net/clion007/safeline-auto-blocker/main/uninstall_auto_blocker.py',
            'path': os.path.join(paths['INSTALL_DIR'], 'uninstall_auto_blocker.py')
        }
    ]
    
    success = True
    for file_info in files_to_download:
        try:
            print(f"正在下载 {os.path.basename(file_info['path'])}...")
            urllib.request.urlretrieve(file_info['url'], file_info['path'])
            
            # 为卸载脚本添加执行权限
            if file_info['path'].endswith('.sh'):
                os.chmod(file_info['path'], 0o755)
                
            print(f"下载文件: {file_info['path']}")
        except Exception as error:
            print(f"下载文件 {file_info['path']} 失败: {str(error)}")
            success = False
    
    return success

# 修复服务名称不一致的问题
def create_service(paths):
    """创建systemd服务"""
    service_file = paths['SERVICE_FILE']
    script_path = os.path.join(paths['INSTALL_DIR'], 'safeline_auto_blocker.py')
    
    service_content = f"""[Unit]
Description=SafeLine Auto Blocker
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {script_path}
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
        
        # 修正服务名称
        os.system('systemctl enable safeline-auto-blocker')
        
        return True
    except Exception as e:
        print(f"创建服务文件失败: {str(e)}")
        return False

# 修复服务启动函数中的服务名称
def start_service():
    """启动服务并检查状态"""
    try:
        # 启动服务
        os.system('systemctl start safeline-auto-blocker')
        
        # 检查服务状态
        status = os.system('systemctl is-active --quiet safeline-auto-blocker')
        if status == 0:
            print("服务启动成功")
            return True
        else:
            print("服务启动失败，请检查日志获取详细信息")
            print("可使用命令: journalctl -u safeline-auto-blocker -n 50")
            return False
    except Exception as error:
        print(f"启动服务时出错: {str(error)}")
        return False

# 修复清理函数中的错误处理
def cleanup_files(paths):
    """清理已安装的文件（回滚操作）"""
    print("正在清理已安装的文件...")
    
    # 禁用服务
    try:
        os.system('systemctl disable safeline-auto-blocker')
        print("禁用服务")
    except Exception as error:
        print(f"禁用服务失败: {str(error)}")
    
    # 删除脚本文件
    for script_file in paths['SCRIPT_FILES']:
        if os.path.exists(script_file):
            try:
                os.remove(script_file)
                print(f"删除文件: {script_file}")
            except Exception as error:
                print(f"删除文件 {script_file} 失败: {str(error)}")
    
    # 删除配置文件
    config_file = paths['INSTALL_CONFIG_FILE']
    if os.path.exists(config_file):
        try:
            os.remove(config_file)
            print(f"删除文件: {config_file}")
        except Exception as error:
            print(f"删除文件 {config_file} 失败: {str(error)}")
    
    # 删除密钥文件
    key_file = paths['INSTALL_KEY_FILE']
    if os.path.exists(key_file):
        try:
            os.remove(key_file)
            print(f"删除文件: {key_file}")
        except Exception as error:
            print(f"删除文件 {key_file} 失败: {str(error)}")
    
    # 删除服务文件
    service_file = paths['SERVICE_FILE']
    if os.path.exists(service_file):
        try:
            os.remove(service_file)
            print(f"删除文件: {service_file}")
            # 重新加载systemd配置
            os.system('systemctl daemon-reload')
        except Exception as error:
            print(f"删除文件 {service_file} 失败: {str(error)}")
    
    print("清理完成，安装已回滚")

# 修改主函数中的服务名称提示
def main():
    """主函数"""
    print_banner()
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='SafeLine Auto Blocker 安装程序')
    parser.add_argument('--offline', action='store_true', help='离线安装模式')
    parser.add_argument('--verify-config', action='store_true', help='验证配置文件')
    args = parser.parse_args()
    
    # 创建目录
    if not create_directories(PATHS):
        print("创建目录失败，安装中止")
        return False
    
    # 下载或复制脚本文件
    if args.offline:
        if not copy_script(PATHS):
            print("复制脚本文件失败，安装中止")
            return False
    else:
        if not download_main_script(PATHS):
            print("下载主脚本文件失败，安装中止")
            return False
        
        # 调用下载模块文件函数
        if not download_module_files(PATHS):
            print("下载模块文件失败，安装中止")
            # 回滚已下载的文件
            cleanup_files(PATHS)
            return False
    
    # 下载其他文件
    if not args.offline:
        if not download_additional_files(PATHS):
            print("下载附加文件失败，安装中止")
            # 回滚已下载的文件
            cleanup_files(PATHS)
            return False

    # 生成密钥
    key = generate_key(PATHS)
    if not key:
        cleanup_files(PATHS)
        return False
    
    # 创建配置文件
    if not create_config(PATHS, key):
        cleanup_files(PATHS)
        return False
    
    # 创建服务
    if not create_service(PATHS):
        cleanup_files(PATHS)
        return False
    
    # 启动服务
    if not start_service():
        print("服务启动失败，但安装已完成。您可以稍后手动启动服务。")
    
    print("\n安装完成！")
    print("您可以使用以下命令管理服务:")
    print("  启动服务: systemctl start safeline-auto-blocker")  # 修复：使用连字符而非下划线
    print("  停止服务: systemctl stop safeline-auto-blocker")   # 修复：使用连字符而非下划线
    print("  查看状态: systemctl status safeline-auto-blocker") # 修复：使用连字符而非下划线
    print("  查看日志: journalctl -u safeline-auto-blocker -f") # 修复：使用连字符而非下划线
    print("\n如需卸载，请运行: python3 /opt/safeline/scripts/uninstall_auto_blocker.py")
    
    return True

if __name__ == '__main__':
    main()
