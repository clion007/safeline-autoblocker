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
}

# 删除配置文件
remove_config() {
    # 删除主配置文件和目录
    if [ -d "$CONFIG_DIR" ]; then
        rm -rf "$CONFIG_FILE" && echo "成功删除配置文件及目录: $CONFIG_DIR" || echo "删除配置文件失败"
    fi
}

# 删除脚本文件
remove_scripts() {
    script_files=(
        "$INSTALL_DIR/api.py"
        "$INSTALL_DIR/config.py"
        "$INSTALL_DIR/logger.py"
        "$INSTALL_DIR/autoblocker.py"
    )
    
    for file in "${script_files[@]}"; do
        if [ -f "$file" ]; then
            rm -f "$file" && echo "删除脚本文件: $file" || echo "删除脚本文件失败: $file"
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
dirs_removed=true
remove_directories || dirs_removed=false

# 卸载结果反馈
echo -e "\n卸载结果:"
echo "服务文件: $([ "$service_removed" = true ] && echo '已删除' || echo '删除失败')"
echo "配置文件: $([ "$config_removed" = true ] && echo '已删除' || echo '删除失败')"
echo "脚本文件: $([ "$script_removed" = true ] && echo '已删除' || echo '删除失败')"

if [ "$service_removed" = true ] && [ "$config_removed" = true ] && [ "$script_removed" = true ]; then
    echo -e "\n✓ 卸载完成！所有组件已成功删除。"
else
    echo -e "\n⚠ 卸载完成，但部分组件删除失败，请检查上述信息。"
fi

# 获取父目录路径
PARENT_DIR=$(dirname "$INSTALL_DIR")

# 删除安装目录及卸载脚本自身
if [ -d "$INSTALL_DIR" ]; then
    echo "删除安装目录: $INSTALL_DIR"
    # 使用后台任务删除，即使脚本被删除也能完成操作
    (sleep 1; rm -rf "$INSTALL_DIR"; 
     # 如果父目录为空，也一并删除
     if [ -d "$PARENT_DIR" ] && [ -z "$(ls -A "$PARENT_DIR")" ]; then
         echo "删除空父目录: $PARENT_DIR"
         rmdir "$PARENT_DIR"
     fi) &
    
    echo "卸载完成，脚本将自动退出..."
    exit 0
fi