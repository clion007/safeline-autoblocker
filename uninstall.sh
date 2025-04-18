#!/bin/bash

# SafeLine AutoBlocker 卸载脚本
# 版本: 2.0.0
# 作者: Clion Nieh
# 日期: 2025.4.16
# 许可证: MIT

# 打印横幅
echo "
╔═══════════════════════════════════════════════╗
║                                               ║
║       SafeLine AutoBlocker 卸载程序           ║
║                                               ║
║       版本: 2.0.0                             ║
║       作者: Clion Nieh                        ║
║                                               ║
╚═══════════════════════════════════════════════╝
"

# 定义路径
CONFIG_DIR="/etc/safeline"
INSTALL_DIR="/opt/safeline/scripts"
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
    fi
}

# 删除配置文件
remove_config() {
    # 删除主配置文件和目录
    if [ -d "$CONFIG_DIR" ]; then
        rm -rf "$CONFIG_DIR" && echo "成功删除配置文件及目录: $CONFIG_DIR" || echo "删除配置文件失败"
    fi
}

# 删除软链接
remove_symlink() {
    if [ -L "/usr/local/bin/safeline-ab" ]; then
        rm -f "/usr/local/bin/safeline-ab" && echo "删除软链接: safeline-ab" || echo "删除软链接失败"
    fi
}

# 执行卸载步骤
stop_service
service_removed=true
remove_service_file || service_removed=false
remove_symlink || symlink_removed=false
config_removed=true
remove_config || config_removed=false

# 删除安装目录下的所有文件（除了当前脚本）
if [ -d "$INSTALL_DIR" ]; then
    # 获取当前脚本的绝对路径
    CURRENT_SCRIPT=$(readlink -f "$0")
    
    # 删除安装目录下除当前脚本外的所有文件
    find "$INSTALL_DIR" -type f -not -path "$CURRENT_SCRIPT" -delete && script_removed=true || script_removed=false
    find "$INSTALL_DIR" -type d -empty -delete 2>/dev/null  # 删除空目录
else
    script_removed=true
fi

# 卸载结果反馈
echo -e "\n卸载结果:"
echo "服务文件: $([ "$service_removed" = true ] && echo '已删除' || echo '删除失败')"
echo "软链接: $([ "$symlink_removed" = true ] && echo '已删除' || echo '删除失败')"
echo "配置文件: $([ "$config_removed" = true ] && echo '已删除' || echo '删除失败')"
echo "脚本文件: $([ "$script_removed" = true ] && echo '已删除' || echo '删除失败')"

if [ "$service_removed" = true ] && [ "$symlink_removed" = true ] && [ "$config_removed" = true ] && [ "$script_removed" = true ]; then
    echo -e "\n✓ 卸载完成！所有组件已成功删除。"
else
    echo -e "\n⚠ 卸载完成，但部分组件删除失败，请检查上述信息。"
fi

# 获取父目录路径
PARENT_DIR=$(dirname "$INSTALL_DIR")

# 创建一个临时清理脚本，在卸载脚本退出后执行
TEMP_CLEANUP_SCRIPT=$(mktemp)
cat > "$TEMP_CLEANUP_SCRIPT" << 'EOF'
#!/bin/bash
# 等待原脚本退出
sleep 2

# 删除卸载脚本
SCRIPT_PATH="$1"
INSTALL_DIR="$2"
PARENT_DIR="$3"

# 删除卸载脚本
[ -f "$SCRIPT_PATH" ] && rm -f "$SCRIPT_PATH"

# 删除安装目录（如果为空）
[ -d "$INSTALL_DIR" ] && rmdir "$INSTALL_DIR" 2>/dev/null

# 删除父目录（如果为空）
[ -d "$PARENT_DIR" ] && rmdir "$PARENT_DIR" 2>/dev/null

# 删除临时脚本自身
rm -f "$0"
EOF

# 设置临时脚本权限
chmod +x "$TEMP_CLEANUP_SCRIPT"

# 后台运行临时清理脚本
"$TEMP_CLEANUP_SCRIPT" "$0" "$INSTALL_DIR" "$PARENT_DIR" &

echo "卸载完成，脚本将自动退出..."
exit 0
