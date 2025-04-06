#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import shutil
import getpass
import subprocess
import configparser
import urllib3
import requests
import json
from cryptography.fernet import Fernet

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 全局变量
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INSTALL_DIR = "/opt/safeline/scripts"
CONFIG_DIR = "/etc/safeline"
LOG_DIR = "/var/log/safeline"
SERVICE_FILE = "/etc/systemd/system/safeline_auto_blocker.service"
CONFIG_FILE = f"{CONFIG_DIR}/auto_blocker.conf"
KEY_FILE = f"{CONFIG_DIR}/auto_blocker.key"
SCRIPT_FILE = f"{INSTALL_DIR}/safeline_auto_blocker.py"

# 攻击类型ID映射
ATTACK_TYPE_NAMES = {
    "0": "SQL注入",
    "1": "XSS",
    "2": "CSRF",
    "3": "SSRF",
    "4": "拒绝服务",
    "5": "后门",
    "6": "反序列化",
    "7": "代码执行",
    "8": "代码注入",
    "9": "命令注入",
    "10": "文件上传",
    "11": "文件包含",
    "21": "扫描器",
    "29": "模板注入"
}

# 默认攻击类型分组
DEFAULT_TYPE_GROUP_MAPPING = {
    # 高危攻击类型加入黑名单组
    "0": "黑名单",
    "5": "黑名单",
    "7": "黑名单",
    "8": "黑名单",
    "9": "黑名单",
    "11": "黑名单",
    "29": "黑名单",
    
    # 低危攻击类型加入人机验证组
    "1": "人机验证",
    "2": "人机验证",
    "3": "人机验证",
    "4": "人机验证",
    "6": "人机验证",
    "10": "人机验证",
    "21": "人机验证"
}

def print_banner():
    """打印安装程序横幅"""
    print("\n" + "=" * 60)
    print("雷池WAF自动封禁工具安装程序")
    print("=" * 60 + "\n")

def check_root():
    """检查是否以root权限运行"""
    if os.geteuid() != 0:
        print("错误: 此脚本需要root权限运行")
        print("请使用 'sudo python3 install_auto_blocker.py' 重新运行")
        sys.exit(1)

def create_directories():
    """创建必要的目录"""
    print("\n创建必要的目录...")
    
    for directory in [INSTALL_DIR, CONFIG_DIR, LOG_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            print(f"✓ 已创建目录: {directory}")
        else:
            print(f"✓ 目录已存在: {directory}")

def generate_key():
    """生成加密密钥"""
    print("\n生成加密密钥...")
    
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    
    # 设置密钥文件权限
    os.chmod(KEY_FILE, 0o600)
    print(f"✓ 密钥已生成并保存到: {KEY_FILE}")
    
    return key

def encrypt_token(token, key):
    """加密API令牌"""
    cipher_suite = Fernet(key)
    encrypted_token = cipher_suite.encrypt(token.encode())
    return encrypted_token.decode()

def verify_api_token(host, port, token, attack_types_filter=None):
    """验证API令牌和攻击类型过滤"""
    print("\n正在验证API令牌...")
    
    headers = {
        "X-SLCE-API-TOKEN": token,
        "Content-Type": "application/json"
    }
    
    # 构建查询参数
    params = {
        "page": 1,
        "page_size": 1
    }
    
    # 如果指定了攻击类型过滤，添加到查询参数中
    if attack_types_filter:
        params["attack_type"] = attack_types_filter
        print(f"正在验证攻击类型过滤: {attack_types_filter}")
    
    try:
        # 发送API请求
        url = f"https://{host}:{port}/api/open/records"
        response = requests.get(
            url,
            headers=headers,
            params=params,
            verify=False,
            timeout=10
        )
        
        if response.status_code == 200:
            print("✓ API令牌验证成功")
            if attack_types_filter:
                print("✓ 攻击类型过滤验证成功")
            return True
        else:
            print(f"✗ API令牌验证失败: HTTP {response.status_code}")
            return False
    
    except Exception as e:
        print(f"✗ API令牌验证异常: {str(e)}")
        return False

def verify_ip_groups(host, port, token, ip_groups):
    """验证IP组是否存在"""
    print("\n正在验证IP组...")
    
    headers = {
        "X-SLCE-API-TOKEN": token,
        "Content-Type": "application/json"
    }
    
    try:
        # 获取IP组列表
        url = f"https://{host}:{port}/api/open/security/ip-groups"
        response = requests.get(
            url,
            headers=headers,
            verify=False,
            timeout=10
        )
        
        if response.status_code != 200:
            print(f"✗ 获取IP组列表失败: HTTP {response.status_code}")
            return False
            
        data = response.json()
        
        if 'data' not in data:
            print("✗ 获取IP组列表失败: 响应格式不正确")
            return False
            
        existing_ip_groups = data.get('data', [])
        existing_ip_group_names = [group.get('name') for group in existing_ip_groups]
        
        print(f"已获取IP组列表: {', '.join(existing_ip_group_names)}")
        
        # 验证所需的IP组是否存在
        missing_groups = []
        for group in ip_groups:
            if group not in existing_ip_group_names:
                missing_groups.append(group)
        
        if missing_groups:
            print(f"✗ 以下IP组不存在: {', '.join(missing_groups)}")
            print("请在雷池WAF管理界面创建这些IP组")
            return False
        
        print("✓ 所有IP组验证成功")
        return True
        
    except Exception as e:
        print(f"✗ 验证IP组异常: {str(e)}")
        return False

def create_config_file(host, port, encrypted_token, default_ip_group, use_type_groups, 
                      attack_types_filter, type_group_mapping, query_interval=60, 
                      max_logs_per_query=100, follow_log_rotation=True, debug_mode=False,
                      max_retries=3, retry_backoff_factor=0.5, ip_cache_expiry=3600):
    """创建配置文件"""
    print("\n创建配置文件...")
    
    config = configparser.ConfigParser()
    
    # 添加默认配置
    config['DEFAULT'] = {
        'SAFELINE_HOST': host,
        'SAFELINE_PORT': str(port),
        'SAFELINE_TOKEN_ENCRYPTED': encrypted_token,
        'DEFAULT_IP_GROUP': default_ip_group,
        'USE_TYPE_GROUPS': str(use_type_groups).lower(),
        'SAFELINE_LOG_FILE': f"{LOG_DIR}/security.log",
        'ATTACK_TYPES_FILTER': attack_types_filter,
        'QUERY_INTERVAL': str(query_interval),
        'MAX_LOGS_PER_QUERY': str(max_logs_per_query),
        'FOLLOW_LOG_ROTATION': str(follow_log_rotation).lower(),
        'DEBUG_MODE': str(debug_mode).lower(),
        'MAX_RETRIES': str(max_retries),
        'RETRY_BACKOFF_FACTOR': str(retry_backoff_factor),
        'IP_CACHE_EXPIRY': str(ip_cache_expiry)
    }
    
    # 添加攻击类型IP组映射
    if use_type_groups:
        config['TYPE_GROUP_MAPPING'] = type_group_mapping
    
    # 写入配置文件
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)
    
    # 设置配置文件权限
    os.chmod(CONFIG_FILE, 0o600)
    print(f"✓ 配置文件已创建: {CONFIG_FILE}")

def create_service_file():
    """创建systemd服务文件"""
    print("\n创建systemd服务文件...")
    
    service_content = f"""[Unit]
Description=SafeLine Auto Blocker
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {SCRIPT_FILE}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    
    with open(SERVICE_FILE, 'w') as f:
        f.write(service_content)
    
    print(f"✓ 服务文件已创建: {SERVICE_FILE}")

def install_script():
    """安装脚本文件"""
    print("\n安装脚本文件...")
    
    # 复制脚本文件
    source_file = os.path.join(SCRIPT_DIR, "safeline_auto_blocker.py")
    if os.path.exists(source_file):
        shutil.copy2(source_file, SCRIPT_FILE)
        os.chmod(SCRIPT_FILE, 0o755)
        print(f"✓ 脚本文件已安装: {SCRIPT_FILE}")
    else:
        print(f"✗ 脚本文件不存在: {source_file}")
        sys.exit(1)

# 优化安装脚本，避免与一键安装脚本功能重复

def check_environment():
    """检查运行环境"""
    print("\n检查运行环境...")
    
    # 检查是否已由一键安装脚本执行过环境检查
    if os.environ.get('QUICK_INSTALL_CHECKED') == '1':
        print("✓ 环境检查已由一键安装脚本完成")
        return
    
    # 检查 Python 版本
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 6):
        print(f"✗ Python 版本不满足要求: 当前版本 {python_version.major}.{python_version.minor}, 需要 3.6+")
        sys.exit(1)
    print(f"✓ Python 版本: {python_version.major}.{python_version.minor}.{python_version.micro}")
    
    # 检查操作系统类型
    if not sys.platform.startswith('linux'):
        print(f"✗ 不支持的操作系统: {sys.platform}")
        print("此脚本仅支持 Linux 系统")
        sys.exit(1)
    print(f"✓ 操作系统: {sys.platform}")
    
    # 检查 systemd
    try:
        subprocess.check_call(["systemctl", "--version"], stdout=subprocess.DEVNULL)
        print("✓ systemd 可用")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("✗ systemd 不可用，无法创建系统服务")
        sys.exit(1)
    
    print("✓ 运行环境检查通过")

def install_dependencies():
    """安装依赖包"""
    print("\n安装依赖包...")
    
    # 检查是否已由一键安装脚本安装过依赖
    if os.environ.get('QUICK_INSTALL_DEPS') == '1':
        print("✓ 依赖包已由一键安装脚本安装")
        return
    
    dependencies = ["requests", "cryptography", "urllib3"]
    
    # 检查 pip 是否可用
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL)
        print("✓ pip 可用")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("✗ pip 不可用，请先安装 pip")
        print("可以尝试: apt-get install python3-pip 或 yum install python3-pip")
        sys.exit(1)
    
    # 安装依赖
    for package in dependencies:
        print(f"安装 {package}...")
        try:
            # 检查包是否已安装
            try:
                __import__(package)
                print(f"✓ {package} 已安装")
                continue
            except ImportError:
                pass
                
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✓ {package} 安装成功")
        except subprocess.CalledProcessError:
            print(f"✗ {package} 安装失败")
            retry = input(f"{package} 安装失败，是否继续? (y/n): ").strip().lower()
            if retry != 'y':
                sys.exit(1)

def enable_service():
    """启用并启动服务"""
    print("\n启用并启动服务...")
    
    try:
        # 重新加载systemd配置
        subprocess.check_call(["systemctl", "daemon-reload"])
        print("✓ systemd配置已重新加载")
        
        # 启用服务
        subprocess.check_call(["systemctl", "enable", "safeline_auto_blocker"])
        print("✓ 服务已设置为开机自启")
        
        # 启动服务
        subprocess.check_call(["systemctl", "start", "safeline_auto_blocker"])
        print("✓ 服务已启动")
        
        # 检查服务状态
        result = subprocess.check_output(["systemctl", "status", "safeline_auto_blocker"])
        if b"Active: active (running)" in result:
            print("✓ 服务运行正常")
        else:
            print("✗ 服务可能未正常运行，请检查日志")
    
    except subprocess.CalledProcessError as e:
        print(f"✗ 服务启动失败: {str(e)}")
        print("请手动检查服务状态: systemctl status safeline_auto_blocker")

def check_and_download_main_script():
    """检查并下载主程序脚本"""
    print("\n检查并下载主程序脚本...")
    
    # 使用gitmirror加速镜像
    base_url = "https://raw.githubusercontent.com/clion007/safeline-auto-blocker/main"
    mirror_url = base_url.replace("https://raw.githubusercontent.com", "https://raw.gitmirror.com")
    
    target_path = os.path.join(INSTALL_DIR, "safeline_auto_blocker.py")
    
    if os.path.exists(target_path):
        print(f"✓ 主程序脚本已存在: {target_path}")
        return
    
    print("下载主程序脚本...")
    try:
        # 首先尝试从镜像下载
        response = requests.get(f"{mirror_url}/safeline_auto_blocker.py", verify=False, timeout=30)
        if response.status_code != 200:
            print("从镜像下载失败，尝试使用原始链接...")
            response = requests.get(f"{base_url}/safeline_auto_blocker.py", verify=False, timeout=30)
        
        if response.status_code == 200:
            with open(target_path, 'w') as f:
                f.write(response.text)
            os.chmod(target_path, 0o755)  # 添加执行权限
            print(f"✓ 已下载并保存到: {target_path}")
        else:
            print(f"✗ 下载失败: HTTP {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"✗ 下载异常: {str(e)}")
        sys.exit(1)

def download_additional_files():
    """下载额外的文件"""
    print("\n下载额外的文件...")
    
    # 使用gitmirror加速镜像
    MIRROR_URL = "https://raw.gitmirror.com/clion007/safeline-auto-blocker/main"
    BACKUP_URL = "https://raw.githubusercontent.com/clion007/safeline-auto-blocker/main"
    
    files_to_download = {
        "uninstall_auto_blocker.py": {
            "url": f"{MIRROR_URL}/uninstall_auto_blocker.py",
            "backup_url": f"{BACKUP_URL}/uninstall_auto_blocker.py",
            "mode": 0o755  # 可执行脚本
        },
        "auto_blocker.conf.example": {
            "url": f"{MIRROR_URL}/auto_blocker.conf.example",
            "backup_url": f"{BACKUP_URL}/auto_blocker.conf.example",
            "mode": 0o644  # 配置文件示例，只需读写权限
        }
    }
    
    for filename, file_info in files_to_download.items():
        target_path = os.path.join(INSTALL_DIR, filename)
        print(f"下载 {filename}...")
        
        try:
            # 首先尝试从镜像下载
            response = requests.get(file_info["url"], verify=False, timeout=30)
            if response.status_code != 200:
                print(f"从镜像下载 {filename} 失败，尝试使用原始链接...")
                response = requests.get(file_info["backup_url"], verify=False, timeout=30)
            
            if response.status_code == 200:
                with open(target_path, 'w') as f:
                    f.write(response.text)
                os.chmod(target_path, file_info["mode"])
                print(f"✓ 已下载并保存到: {target_path}")
            else:
                print(f"✗ 下载 {filename} 失败: HTTP {response.status_code}")
        except Exception as e:
            print(f"✗ 下载 {filename} 异常: {str(e)}")

def main():
    """主函数"""
    print_banner()
    check_environment()
    
    # 检查 root 权限
    check_root()
    
    # 安装依赖包
    install_dependencies()
    
    # 检查并下载主程序脚本
    check_and_download_main_script()
    
    # 创建目录
    create_directories()
    
    # 安装脚本
    install_script()
    
    # 下载额外的文件
    download_additional_files()
    
    # 获取配置信息
    print("\n请输入雷池WAF API配置信息:")
    host = input("雷池API主机地址 [localhost]: ").strip() or "localhost"
    port = input("雷池API端口 [9443]: ").strip() or "9443"
    token = getpass.getpass("雷池API令牌 (输入时不显示): ").strip()
    
    # 验证API令牌
    if not verify_api_token(host, port, token):
        retry = input("API令牌验证失败，是否重试? (y/n): ").strip().lower()
        if retry == 'y':
            token = getpass.getpass("雷池API令牌 (输入时不显示): ").strip()
            if not verify_api_token(host, port, token):
                print("API令牌验证再次失败，安装中止")
                sys.exit(1)
        else:
            print("安装中止")
            sys.exit(1)
    
    # 获取IP组配置
    default_ip_group = input("默认IP组名称 [人机验证]: ").strip() or "人机验证"
    use_type_groups_input = input("是否为不同攻击类型配置不同IP组? (y/n) [y]: ").strip().lower() or "y"
    use_type_groups = (use_type_groups_input == 'y')
    
    # 验证IP组
    required_ip_groups = set()
    required_ip_groups.add(default_ip_group)
    
    type_group_mapping = {}
    if use_type_groups:
        print("\n默认攻击类型IP组映射:")
        for attack_id, group in DEFAULT_TYPE_GROUP_MAPPING.items():
            attack_name = ATTACK_TYPE_NAMES.get(attack_id, f"未知类型({attack_id})")
            print(f"攻击类型: {attack_name}(ID:{attack_id}) -> IP组: {group}")
            required_ip_groups.add(group)
            type_group_mapping[attack_id] = group
        
        customize = input("\n是否自定义攻击类型IP组映射? (y/n) [n]: ").strip().lower() or "n"
        if customize == 'y':
            print("\n请为每种攻击类型指定IP组 (直接回车使用默认值):")
            for attack_id, attack_name in ATTACK_TYPE_NAMES.items():
                default_group = DEFAULT_TYPE_GROUP_MAPPING.get(attack_id, default_ip_group)
                group = input(f"攻击类型: {attack_name}(ID:{attack_id}) [默认: {default_group}]: ").strip() or default_group
                type_group_mapping[attack_id] = group
                required_ip_groups.add(group)
    
    # 验证IP组是否存在
    if not verify_ip_groups(host, port, token, required_ip_groups):
        create_groups = input("是否继续安装? (y/n) [n]: ").strip().lower() or "n"
        if create_groups != 'y':
            print("安装中止")
            sys.exit(1)
    
    # 获取攻击类型过滤配置
    filter_types = input("\n是否只监控特定类型的攻击? (y/n) [n]: ").strip().lower() or "n"
    attack_types_filter = ""
    if filter_types == 'y':
        print("\n可用的攻击类型:")
        for attack_id, attack_name in ATTACK_TYPE_NAMES.items():
            print(f"ID: {attack_id} - {attack_name}")
        
        attack_types_filter = input("\n请输入要监控的攻击类型ID (多个ID用逗号分隔): ").strip()
        
        # 验证攻击类型过滤
        if attack_types_filter and not verify_api_token(host, port, token, attack_types_filter):
            print("攻击类型过滤验证失败，将不使用过滤")
            attack_types_filter = ""
    
    # 获取高级配置
    advanced = input("\n是否配置高级选项? (y/n) [n]: ").strip().lower() or "n"
    query_interval = 60
    max_logs_per_query = 100
    follow_log_rotation = True
    debug_mode = False
    max_retries = 3
    retry_backoff_factor = 0.5
    ip_cache_expiry = 3600
    
    if advanced == 'y':
        query_interval = int(input("API查询间隔 (秒) [60]: ").strip() or "60")
        max_logs_per_query = int(input("每次查询的最大日志数量 [100]: ").strip() or "100")
        follow_log_rotation_input = input("是否跟踪日志轮转 (y/n) [y]: ").strip().lower() or "y"
        follow_log_rotation = (follow_log_rotation_input == 'y')
        debug_mode_input = input("是否启用调试模式 (y/n) [n]: ").strip().lower() or "n"
        debug_mode = (debug_mode_input == 'y')
        max_retries = int(input("API请求最大重试次数 [3]: ").strip() or "3")
        retry_backoff_factor = float(input("重试间隔因子 [0.5]: ").strip() or "0.5")
        ip_cache_expiry = int(input("IP缓存过期时间 (秒) [3600]: ").strip() or "3600")
    
    # 生成密钥
    key = generate_key()
    
    # 加密令牌
    encrypted_token = encrypt_token(token, key)
    
    # 创建配置文件
    create_config_file(
        host, port, encrypted_token, default_ip_group, use_type_groups, 
        attack_types_filter, type_group_mapping, query_interval, 
        max_logs_per_query, follow_log_rotation, debug_mode,
        max_retries, retry_backoff_factor, ip_cache_expiry
    )
    
    # 创建服务文件
    create_service_file()
    
    # 启用并启动服务
    enable_service()
    
    print("\n" + "=" * 60)
    print("安装完成!")
    print("=" * 60)
    print(f"配置文件: {CONFIG_FILE}")
    print(f"脚本文件: {SCRIPT_FILE}")
    print(f"日志文件: {LOG_DIR}/auto_blocker.log")
    print("\n查看服务状态: systemctl status safeline_auto_blocker")
    print("查看日志: tail -f /var/log/safeline/auto_blocker.log")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()