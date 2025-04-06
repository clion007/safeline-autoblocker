#!/bin/bash

# SafeLine Auto Blocker 一键安装脚本
# 作者: Clion Nieh
# 版本: 1.0.0

# 打印横幅
echo "=================================================="
echo "  SafeLine Auto Blocker 一键安装脚本"
echo "=================================================="
echo "本脚本将自动下载并安装 SafeLine Auto Blocker"
echo "=================================================="

# 检查是否以root权限运行
if [ "$(id -u)" != "0" ]; then
   echo "错误: 此脚本需要root权限运行"
   echo "请使用 'sudo bash' 或 'sudo sh' 运行此脚本"
   exit 1
fi

# 检查系统环境
echo -e "\n正在检查系统环境..."

# 检查操作系统
if [ ! -f /etc/os-release ]; then
    echo "错误: 无法确定操作系统类型"
    exit 1
fi

# 检查Python版本
if ! command -v python3 &> /dev/null; then
    echo "错误: Python3 未安装"
    echo "正在尝试安装 Python3..."
    
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y python3 python3-pip
    elif command -v yum &> /dev/null; then
        yum install -y python3 python3-pip
    else
        echo "错误: 无法安装 Python3，请手动安装后重试"
        exit 1
    fi
fi

# 检查Python版本是否>=3.6
python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if [ "$(echo "$python_version < 3.6" | bc)" -eq 1 ]; then
    echo "错误: Python 版本必须 >= 3.6，当前版本: $python_version"
    exit 1
fi
echo "✓ Python 版本: $python_version"

# 检查systemd
if ! command -v systemctl &> /dev/null; then
    echo "错误: systemd 未安装，无法创建系统服务"
    exit 1
fi
echo "✓ systemd 可用"

# 创建临时目录
temp_dir=$(mktemp -d)
cd "$temp_dir" || exit 1

# 下载安装脚本
echo -e "\n正在下载安装脚本..."
# 使用gitmirror加速镜像
MIRROR_URL="https://raw.gitmirror.com/clion007/safeline-auto-blocker/main"

if command -v curl &> /dev/null; then
    curl -s -o install_auto_blocker.py "${MIRROR_URL}/install_auto_blocker.py"
elif command -v wget &> /dev/null; then
    wget -q -O install_auto_blocker.py "${MIRROR_URL}/install_auto_blocker.py"
else
    echo "错误: 未找到 curl 或 wget，无法下载文件"
    echo "请安装 curl 或 wget 后重试"
    exit 1
fi

if [ ! -f install_auto_blocker.py ]; then
    echo "错误: 下载安装脚本失败"
    echo "尝试使用原始链接..."
    
    # 备用链接使用GitHub原始链接
    BACKUP_URL="https://raw.githubusercontent.com/clion007/safeline-auto-blocker/main"
    
    if command -v curl &> /dev/null; then
        curl -s -o install_auto_blocker.py "${BACKUP_URL}/install_auto_blocker.py"
    elif command -v wget &> /dev/null; then
        wget -q -O install_auto_blocker.py "${BACKUP_URL}/install_auto_blocker.py"
    fi
    
    if [ ! -f install_auto_blocker.py ]; then
        echo "错误: 备用链接下载也失败，请检查网络连接"
        exit 1
    fi
    echo "✓ 使用备用链接下载成功"
else
    echo "✓ 安装脚本下载成功"
fi

# 安装依赖
echo -e "\n正在安装依赖..."
python3 -m pip install requests cryptography urllib3 -q

# 运行安装脚本
echo -e "\n正在运行安装脚本..."
chmod +x install_auto_blocker.py
# 设置环境变量，告知安装脚本环境检查和依赖安装已完成
export QUICK_INSTALL_CHECKED=1
export QUICK_INSTALL_DEPS=1
python3 install_auto_blocker.py

# 清理临时文件
cd / || exit 1
rm -rf "$temp_dir"

echo -e "\n=================================================="
echo "  SafeLine Auto Blocker 安装完成!"
echo "=================================================="
echo "如需查看使用方法，请参考: https://github.com/clion007/safeline-auto-blocker"
echo "=================================================="