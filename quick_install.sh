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

# 检查是否为root用户
if [ "$(id -u)" != "0" ]; then
   echo "错误: 请使用root权限运行此脚本"
   exit 1
fi

# 安装依赖
echo "正在安装依赖..."
if command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y python3 python3-pip
elif command -v yum &> /dev/null; then
    yum install -y python3 python3-pip
else
    echo "不支持的系统，请手动安装Python3和pip"
    exit 1
fi

# 安装Python依赖
echo "正在安装Python依赖..."
pip3 install requests cryptography

# 创建临时目录
mkdir -p /tmp

# 下载安装脚本
echo "正在下载安装脚本..."
wget --tries=3 --timeout=15 --retry-connrefused -O /tmp/install_auto_blocker.py https://ghproxy.com/https://raw.githubusercontent.com/clion007/safeline-auto-blocker/main/install_auto_blocker.py

if [ $? -ne 0 ]; then
    echo "下载安装脚本失败，安装中止"
    exit 1
fi

# 添加执行权限
chmod +x /tmp/install_auto_blocker.py

# 运行安装脚本
echo "正在运行安装脚本..."
python3 /tmp/install_auto_blocker.py

if [ $? -ne 0 ]; then
    echo "安装脚本执行失败"
    exit 1
fi

# 清理临时文件
rm -f /tmp/install_auto_blocker.py

echo "
安装完成！您可以使用以下命令管理服务:
  启动服务: systemctl start safeline-auto-blocker
  停止服务: systemctl stop safeline-auto-blocker
  查看状态: systemctl status safeline-auto-blocker
  查看日志: journalctl -u safeline-auto-blocker -f
"