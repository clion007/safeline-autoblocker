#!/bin/bash

# SafeLine AutoBlocker 卸载脚本
# 版本: 1.2.0
# 作者: Clion Nieh
# 日期: 2025.4.6
# 许可证: MIT

# 打印横幅
echo "
╔═══════════════════════════════════════════════╗
║                                               ║
║       SafeLine AutoBlocker 卸载程序           ║
║                                               ║
║       版本: 1.2.0                             ║
║       作者: Clion Nieh                        ║
║                                               ║
╚═══════════════════════════════════════════════╝
"

# 定义路径
CONFIG_DIR="/etc/safeline"
INSTALL_DIR="/opt/safeline/scripts"
INSTALL_LOG_DIR="/var/log/safeline"
CONFIG_FILE="$CONFIG_DIR/setting.conf"
KEY_FILE="$CONFIG_DIR/token.key"
TOKEN_FILE="$CONFIG_DIR/token.enc"
CONFIG_EXAMPLE="$CONFIG_DIR/setting.conf.example"
SERVICE_FILE="/etc/systemd/system/safeline-autoblocker.service"

# 检查是否为root用户
if [ "$(id -u)" != "0" ]; then
    echo "错误: 请使用root权限运行此脚本"
    exit 1
fi

# 确认卸载
read -p "确定要卸载 SafeLine AutoBlocker? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "卸载已取消"
    exit 0
fi

echo -e "\n开始卸载过程..."

# 检查服务是否存在
check_service_exists() {
    systemctl list-unit-files | grep -q safeline-autoblocker.service
    return $?
}

# 检查服务是否运行
check_service_running() {
    systemctl is-active --quiet safeline-autoblocker
    return $?
}

# 停止服务
stop_service() {
    # 检查服务是否存在
    if ! check_service_exists; then
        echo "服务不存在，跳过停止服务步骤"
        return 0
    fi
    
    # 检查服务是否在运行
    if ! check_service_running; then
        echo "服务已经停止，跳过停止服务步骤"
        return 0
    fi
    
    # 尝试停止服务
    for attempt in {1..3}; do
        echo "停止服务尝试 ($attempt/3)..."
        systemctl stop safeline-autoblocker
        systemctl disable safeline-autoblocker
        
        # 验证服务状态
        if ! check_service_running; then
            echo "服务已成功停止"
            return 0
        fi
        sleep 2
    done
    
    echo "警告: 无法完全停止服务，将尝试强制删除相关文件"
    return 0
}

# 删除服务文件
remove_service_file() {
    if [ -f "$SERVICE_FILE" ]; then
        rm -f "$SERVICE_FILE" && echo "删除服务文件: $SERVICE_FILE" || echo "删除服务文件失败"
        systemctl daemon-reload
    else
        echo "服务文件不存在: $SERVICE_FILE"
    fi
}

# 删除配置文件
remove_config() {
    # 删除主配置文件
    if [ -f "$CONFIG_FILE" ]; then
        rm -f "$CONFIG_FILE" && echo "删除配置文件: $CONFIG_FILE" || echo "删除配置文件失败"
    fi
    
    # 删除密钥文件
    if [ -f "$KEY_FILE" ]; then
        rm -f "$KEY_FILE" && echo "删除密钥文件: $KEY_FILE" || echo "删除密钥文件失败"
    fi
    
    # 删除令牌文件
    if [ -f "$TOKEN_FILE" ]; then
        rm -f "$TOKEN_FILE" && echo "删除令牌文件: $TOKEN_FILE" || echo "删除令牌文件失败"
    fi
    
    # 删除配置示例文件
    if [ -f "$CONFIG_EXAMPLE" ]; then
        rm -f "$CONFIG_EXAMPLE" && echo "删除配置示例文件: $CONFIG_EXAMPLE" || echo "删除配置示例文件失败"
    fi
    
    # 删除隐藏文件
    hidden_files=("$CONFIG_DIR/.safeline-autoblocker" "$INSTALL_DIR/.safeline-cache")
    for file in "${hidden_files[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file" && echo "删除隐藏文件: $file" || echo "删除隐藏文件失败: $file"
        fi
    done
}

# 删除脚本文件
remove_scripts() {
    script_files=(
        "$INSTALL_DIR/safeline-autoblocker.py"
        "$INSTALL_DIR/api.py"
        "$INSTALL_DIR/config.py"
        "$INSTALL_DIR/logger.py"
    )
    
    for file in "${script_files[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file" && echo "删除脚本文件: $file" || echo "删除脚本文件失败: $file"
        fi
    done
}

# 删除日志文件
remove_logs() {
    if [ -d "$INSTALL_LOG_DIR" ]; then
        rm -rf "$INSTALL_LOG_DIR" && echo "删除日志目录: $INSTALL_LOG_DIR" || echo "删除日志目录失败"
    else
        echo "日志目录不存在: $INSTALL_LOG_DIR"
    fi
}

# 删除目录
remove_directories() {
    # 按长度排序，确保先删除子目录
    directories=(
        "$INSTALL_DIR"
        "$CONFIG_DIR"
        "$INSTALL_LOG_DIR"
        "$(dirname "$INSTALL_DIR")"
        "$(dirname "$INSTALL_LOG_DIR")"
    )
    
    # 等待1秒确保文件操作完成
    sleep 1
    
    for dir in "${directories[@]}"; do
        if [ -d "$dir" ]; then
            rm -rf "$dir" && echo "成功删除目录: $dir" || echo "删除目录失败: $dir"
        else
            echo "目录不存在: $dir"
        fi
    done
}

# 执行卸载步骤
stop_service
service_removed=true
remove_service_file || service_removed=false
config_removed=true
remove_config || config_removed=false
script_removed=true
remove_scripts || script_removed=false
logs_removed=true
remove_logs || logs_removed=false
dirs_removed=true
remove_directories || dirs_removed=false

# 卸载结果反馈
echo -e "\n卸载结果:"
echo "服务文件: $([ "$service_removed" = true ] && echo '已删除' || echo '删除失败')"
echo "配置文件: $([ "$config_removed" = true ] && echo '已删除' || echo '删除失败')"
echo "脚本文件: $([ "$script_removed" = true ] && echo '已删除' || echo '删除失败')"
echo "日志文件: $([ "$logs_removed" = true ] && echo '已删除' || echo '删除失败')"
echo "相关目录: $([ "$dirs_removed" = true ] && echo '已清理' || echo '部分目录未清理')"

if [ "$service_removed" = true ] && [ "$config_removed" = true ] && [ "$script_removed" = true ] && [ "$logs_removed" = true ] && [ "$dirs_removed" = true ]; then
    echo -e "\n✓ 卸载完成！所有组件已成功删除。"
else
    echo -e "\n⚠ 卸载完成，但部分组件删除失败，请检查上述信息。"
fi

# 最后删除自身
echo "卸载脚本将自动删除自身..."
rm -f "$0"