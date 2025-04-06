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
def download_module_files(paths):
    """下载模块文件"""
    module_files = [
        {
            'url': 'https://raw.gitmirror.com/clion007/safeline-auto-blocker/main/api.py',
            'path': os.path.join(paths['INSTALL_DIR'], 'api.py')
        },
        {
            'url': 'https://raw.gitmirror.com/clion007/safeline-auto-blocker/main/config.py',
            'path': os.path.join(paths['INSTALL_DIR'], 'config.py')
        },
        {
            'url': 'https://raw.gitmirror.com/clion007/safeline-auto-blocker/main/logger.py',
            'path': os.path.join(paths['INSTALL_DIR'], 'logger.py')
        }
    ]
    
    success = True
    for file_info in module_files:
        try:
            print(f"正在下载 {os.path.basename(file_info['path'])}...")
            urllib.request.urlretrieve(file_info['url'], file_info['path'])
            print(f"下载文件: {file_info['path']}")
        except Exception as error:
            print(f"下载文件 {file_info['path']} 失败: {str(error)}")
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
def create_config(paths):
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
        
        # 启用服务
        os.system('systemctl enable safeline_auto_blocker')
        
        return True
    except Exception as e:
        print(f"创建服务文件失败: {str(e)}")
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
    try:
        print("正在下载主监控脚本...")
        urllib.request.urlretrieve(
            'https://raw.gitmirror.com/clion007/safeline-auto-blocker/main/safeline_auto_blocker.py',
            script_path
        )
        os.chmod(script_path, 0o755)  # 添加执行权限
        print(f"下载脚本文件: {script_path}")
        return True
    except Exception as error:
        print(f"下载脚本文件失败: {str(error)}")
        return False

def download_additional_files(paths):
    """下载配置示例文件和卸载脚本文件"""
    files_to_download = [
        {
            'url': 'https://raw.gitmirror.com/clion007/safeline-auto-blocker/main/auto_blocker.conf.example',
            'path': paths['INSTALL_CONFIG_EXAMPLE']
        },
        {
            'url': 'https://raw.gitmirror.com/clion007/safeline-auto-blocker/main/uninstall_auto_blocker.py',
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
    except Exception as error:
        print(f"启动服务时出错: {str(error)}")
        return False

def main():
    """主函数"""
    print_banner()
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='SafeLine Auto Blocker 安装程序')
    parser.add_argument('--offline', action='store_true', help='离线安装模式')
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
            print("下载模块文件失败，安装可能不完整")
            # 继续安装，因为主脚本已下载成功
    
    # 下载其他文件
    if not args.offline:
        if not download_additional_files(PATHS):
            print("下载附加文件失败，安装可能不完整")
            # 继续安装，因为主要文件已下载成功

    # 生成密钥
    key = generate_key(PATHS)
    if not key:
        return
    
    # 创建配置文件
    if not create_config(key, PATHS):
        return
    
    # 创建服务
    if not create_service(PATHS):
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
    print("\n如需卸载，请运行: python3 /opt/safeline/scripts/uninstall_auto_blocker.py")

if __name__ == '__main__':
    main()

# 安装后验证配置
if args.verify_config:
    from config import parse_config, validate_config
    # 修改: 直接使用安装路径中的配置文件
    config_file = PATHS['INSTALL_CONFIG_FILE']
    config = parse_config(config_file)
    if config and validate_config(config):
        print("配置验证通过")
    else:
        print("配置验证失败")
        