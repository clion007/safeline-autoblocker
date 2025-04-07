#!/bin/bash

# SafeLine Auto Blocker 一键安装脚本
# 版本: 1.2.0
# 作者: Clion Nieh
# 日期: 2025.4.6
# 许可证: MIT

# 打印横幅
echo "
╔═══════════════════════════════════════════════╗
║                                               ║
║       SafeLine Auto Blocker 一键安装          ║
║                                               ║
║       版本: 1.2.0                             ║
║       作者: Clion Nieh                        ║
║                                               ║
╚═══════════════════════════════════════════════╝
"

# 在脚本开头添加清理函数
cleanup() {
    echo "正在清理临时文件..."
    rm -f /tmp/install-autoblocker.py
}

# 检查是否为root用户
if [ "$(id -u)" != "0" ]; then
   echo "错误: 请使用root权限运行此脚本"
   cleanup  # 清理调用
   exit 1
fi

# 安装依赖
echo "正在安装依赖..."
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y python3 python3-pip
elif command -v dnf &> /dev/null; then
    dnf install -y python3 python3-pip
elif command -v yum &> /dev/null; then
    yum install -y python3 python3-pip
else
    echo "不支持的系统，请手动安装Python3和pip"
    cleanup  # 清理调用
    exit 1
fi

# 安装Python依赖
echo "正在安装Python依赖..."
pip3 install requests cryptography

# 创建临时目录
mkdir -p /tmp

# 定义下载函数，支持curl和wget，带重试逻辑
download_file() {
    local url=$1
    local output_file=$2
    local max_retries=3
    local retry_count=0
    
    echo "正在下载: $url"
    
    # 检查是否有curl
    if command -v curl &> /dev/null; then
        while [ $retry_count -lt $max_retries ]; do
            if curl --fail --silent --location --connect-timeout 15 --retry 3 --retry-delay 2 --output "$output_file" "$url"; then
                echo "下载成功!"
                return 0
            else
                retry_count=$((retry_count + 1))
                if [ $retry_count -lt $max_retries ]; then
                    echo "下载失败，正在尝试第 $retry_count 次重试..."
                    sleep 2
                else
                    echo "下载失败，已达到最大重试次数 ($max_retries)"
                fi
            fi
        done
    # 如果没有curl，使用wget
    elif command -v wget &> /dev/null; then
        if wget --quiet --tries=3 --timeout=15 --retry-connrefused --output-document="$output_file" "$url"; then
            echo "下载成功!"
            return 0
        else
            echo "下载失败"
        fi
    else
        echo "错误: 系统中未找到curl或wget，无法下载文件"
    fi
    
    return 1
}

# 下载安装脚本
echo "正在下载安装脚本..."
if ! download_file "https://gitee.com/clion007/safeline-autoblocker/raw/main/install-autoblocker.py" "/tmp/install-autoblocker.py"; then
    echo "下载安装脚本失败，安装中止"
    cleanup  # 清理调用
    exit 1
fi

# 添加执行权限
chmod +x /tmp/install-autoblocker.py

# 运行安装脚本
echo "正在运行安装脚本..."
if ! python3 /tmp/install-autoblocker.py; then
    echo "安装脚本执行失败"
    cleanup  # 清理调用
    exit 1
fi

# 清理临时文件
cleanup  # 清理调用

echo "
安装完成！您可以使用以下命令管理服务:
  启动服务: systemctl start safeline-autoblocker
  停止服务: systemctl stop safeline-autoblocker
  查看状态: systemctl status safeline-autoblocker
  查看日志: journalctl -u safeline-autoblocker -f
"
