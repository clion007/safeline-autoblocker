#!/bin/bash

# SafeLine AutoBlocker 安装脚本
# 版本: 2.0.0
# 作者: Clion Nieh
# 日期: 2025.4.16
# 许可证: MIT

# 定义颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 无颜色

# 定义路径和文件
CONFIG_DIR="/etc/safeline"
CONFIG_FILE="$CONFIG_DIR/setting.conf"
LOG_CONFIG_FILE="$CONFIG_DIR/log.yaml"
KEY_FILE="$CONFIG_DIR/token.key"
TOKEN_FILE="$CONFIG_DIR/token.enc"
MAIN_SCRIPT="autoblocker.py"
UNINSTALL_SCRIPT="uninstall.sh"
INSTALL_DIR="/opt/safeline/scripts"
SERVICE_FILE="/etc/systemd/system/safeline-autoblocker.service"

# 定义下载源
REPO_URL="https://gitee.com/clion007/safeline-autoblocker/raw/main"

# 打印横幅
print_banner() {
    echo -e "
    ${BLUE}╔═══════════════════════════════════════════════╗
    ║                                               ║
    ║       SafeLine AutoBlocker 安装程序           ║
    ║                                               ║
    ║       版本: 2.0.0                             ║
    ║       作者: Clion Nieh                        ║
    ║                                               ║
    ╚═══════════════════════════════════════════════╝${NC}
    "
}

# 打印安装步骤
print_step() {
    local step_number=$1
    local total_steps=$2
    local step_name=$3
    
    echo -e "\n${BLUE}[$step_number/$total_steps] $step_name${NC}"
    echo "=================================================="
}

# 检查是否为root用户
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo -e "${RED}错误: 请使用root权限运行此脚本${NC}"
        exit 1
    fi
}

# 检查依赖
check_dependencies() {
    local missing_deps=()
    
    # 检查Python3
    if ! command -v python3 &> /dev/null; then
        missing_deps+=("python3")
    fi
    
    # 检查pip3
    if ! command -v pip3 &> /dev/null; then
        missing_deps+=("pip3")
    fi
    
    # 检查curl或wget
    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        missing_deps+=("curl或wget")
    fi
    
    # 如果有缺失的依赖，尝试安装
    if [ ${#missing_deps[@]} -gt 0 ]; then
        echo -e "${YELLOW}检测到缺少以下依赖: ${missing_deps[*]}${NC}"
        echo "尝试自动安装依赖..."
        
        # 检测系统类型
        if command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            apt-get update
            apt-get install -y python3 python3-pip curl
        elif command -v yum &> /dev/null; then
            # CentOS/RHEL
            yum install -y python3 python3-pip curl
        elif command -v dnf &> /dev/null; then
            # Fedora
            dnf install -y python3 python3-pip curl
        else
            echo -e "${RED}无法自动安装依赖，请手动安装以下软件包后重试: ${missing_deps[*]}${NC}"
            exit 1
        fi
        
        echo -e "${GREEN}依赖安装完成${NC}"
    fi
    
    echo "安装Python依赖..."
    pip3 install cryptography pyyaml requests
}

# 创建目录
create_directories() {
    print_step 1 6 "创建必要目录"
    
    local directories=("$INSTALL_DIR" "$CONFIG_DIR")
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        if [ $? -eq 0 ]; then
            chmod 755 "$dir"
            echo -e "${GREEN}创建目录: $dir (权限:755)${NC}"
        else
            echo -e "${RED}目录创建失败: $dir${NC}"
            return 1
        fi
    done
    
    return 0
}

# 下载文件
download_files() {
    print_step 2 6 "获取程序文件"
    
    # 定义需要下载的文件列表
    local script_files=(
        "api.py"
        "LICENSE"
        "logger.py"
        "README.md"
        "version.py"
        "factory.py"
        "configer.py"
        "$MAIN_SCRIPT"
        "$UNINSTALL_SCRIPT"
    )
    
    # 下载主脚本和模块文件
    for file in "${script_files[@]}"; do
        echo "正在下载: $file"
        local destination="$INSTALL_DIR/$file"
        
        if command -v curl &> /dev/null; then
            # 使用curl下载
            curl --fail --silent --location --connect-timeout 15 --retry 3 --output "$destination" "$REPO_URL/$file"
        elif command -v wget &> /dev/null; then
            # 使用wget下载
            wget --quiet --tries=3 --timeout=15 --output-document="$destination" "$REPO_URL/$file"
        else
            echo -e "${RED}错误: 系统中未找到curl或wget${NC}"
            return 1
        fi
        
        if [ $? -ne 0 ]; then
            echo -e "${RED}下载失败: $file${NC}"
            return 1
        fi
        # 设置执行权限（排除文档文件）
        if [ "$file" != "README.md" ] && [ "$file" != "LICENSE" ]; then
            chmod 755 "$destination"
            # 为主脚本添加 shebang
            if [ "$file" = "$MAIN_SCRIPT" ]; then
                sed -i '1i#!/usr/bin/env python3' "$destination"
                # 创建软链接
                ln -sf "$INSTALL_DIR/$MAIN_SCRIPT" /usr/local/bin/safeline-ab
                chmod 755 /usr/local/bin/safeline-ab
            fi
        fi
    done
    
    echo -e "${GREEN}所有文件下载完成${NC}"
    return 0
}

# 生成加密密钥
generate_key() {
    # 使用Python生成Fernet密钥并确保正确的格式
    local key=$(python3 -c '
from cryptography.fernet import Fernet
import base64
key = Fernet.generate_key()
print(key.decode())
')
    
    if [ -z "$key" ]; then
        echo -e "${RED}生成加密密钥失败${NC}"
        return 1
    fi
    
    # 将密钥保存到文件
    echo -n "$key" > "$KEY_FILE"
    chmod 600 "$KEY_FILE"
    echo -e "${GREEN}生成加密密钥: $KEY_FILE${NC}"
    return 0
}

# 加密令牌
encrypt_token() {
    local token=$1
    local key=$(cat "$KEY_FILE")
    
    # 使用Python加密令牌，确保正确处理密钥格式
    local encrypted_token=$(python3 -c '
import sys, base64
from cryptography.fernet import Fernet
token, key = sys.argv[1:]
f = Fernet(key.encode())
print(f.encrypt(token.encode()).decode())
' "$token" "$key")
    
    if [ -z "$encrypted_token" ]; then
        echo -e "${RED}加密令牌失败${NC}"
        return 1
    fi
    
    # 将加密令牌保存到文件
    echo -n "$encrypted_token" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    echo -e "${GREEN}创建加密令牌文件: $TOKEN_FILE${NC}"
    
    return 0
}

# 获取用户输入
get_user_input() {
    local prompt=$1
    local default=$2
    local is_password=$3
    local choices=$4

    # 构造提示信息
    if [ -n "$default" ]; then
        prompt="$prompt (默认: $default): "  
    elif [ "$is_password" = "true" ]; then
        prompt="$prompt (隐藏输入): "
    else
        prompt="$prompt: "
    fi
    
    local value
    while true; do
        # 使用 /dev/tty 直接与终端交互
        echo -en "${BLUE}$prompt${NC}" > /dev/tty        
        if [ "$is_password" = "true" ]; then
            read -s value < /dev/tty
            echo > /dev/tty
        else
            read value < /dev/tty
        fi
        
        value=$(echo "$value" | xargs) # 去除前后空格
        
        # 使用默认值
        if [ -z "$value" ] && [ -n "$default" ]; then
            echo "$default"
            return 0
        fi
        
        # 验证选择
        if [ -n "$choices" ] && [[ ! "$choices" =~ $(echo "$value" | tr '[:upper:]' '[:lower:]') ]]; then
            echo -e "${YELLOW}请输入有效的选项: $choices${NC}" > /dev/tty
            continue
        fi
        
        # 验证非空
        if [ -z "$value" ] && [ -z "$default" ]; then
            echo -e "${YELLOW}此项不能为空，请重新输入${NC}" > /dev/tty
            continue
        fi
        
        echo "$value"
        return 0
    done
}

# 创建配置文件
create_config() {
    print_step 3 6 "配置信息设置"
    
    echo -e "\n${BLUE}基础配置:${NC}"
    echo "------------------------------------------------"
    local host=$(get_user_input "雷池API地址" "localhost" "false")
    local port=$(get_user_input "雷池API端口" "9443" "false")
    local api_prefix=$(get_user_input "API前缀路径" "/api/open" "false")
    local token=$(get_user_input "雷池API令牌" "" "false")
    
    echo -e "\n${BLUE}IP组配置:${NC}"
    echo "------------------------------------------------"
    local high_risk_ip_group=$(get_user_input "高危攻击IP组名称" "黑名单" "false")
    local low_risk_ip_group=$(get_user_input "低危攻击IP组名称" "人机验证" "false")
    
    echo -e "\n${BLUE}性能配置:${NC}"
    echo "------------------------------------------------"
    local query_interval=$(get_user_input "API查询间隔（秒）" "60" "false")
    local max_logs=$(get_user_input "每页查询最大日志数量" "100" "false")
    local max_pages=$(get_user_input "每次查询日志最大页数" "5" "false")
    local log_retention_days=$(get_user_input "日志保留天数（0表示永久保留）" "30" "false")
    
    # 日志级别选择
    echo -e "\n${BLUE}日志级别配置:${NC}"
    echo "------------------------------------------------"
    echo -e "  ${GREEN}1)${NC} DEBUG    - 调试信息    [最详细的日志记录]"
    echo -e "  ${GREEN}2)${NC} INFO     - 一般信息    [默认级别]"
    echo -e "  ${GREEN}3)${NC} WARNING  - 警告信息    [仅记录警告及以上]"
    echo -e "  ${GREEN}4)${NC} ERROR    - 错误信息    [仅记录错误]"
    echo -e "  ${GREEN}5)${NC} CRITICAL - 严重错误    [仅记录严重错误]"
    echo "------------------------------------------------"
    
    local log_level_choice
    while true; do
        echo -en "${BLUE}请输入选项 [1-5] (默认: 2): ${NC}" > /dev/tty
        read log_level_choice < /dev/tty
        log_level_choice=${log_level_choice:-2}
        
        case $log_level_choice in
            1) log_level="DEBUG"; break ;;
            2) log_level="INFO"; break ;;
            3) log_level="WARNING"; break ;;
            4) log_level="ERROR"; break ;;
            5) log_level="CRITICAL"; break ;;
            *) echo -e "${YELLOW}请输入1-5之间的数字${NC}" > /dev/tty ;;
        esac
    done
    
    echo -e "${GREEN}已选择日志级别: $log_level${NC}" > /dev/tty
    
    # 生成密钥
    local key=$(generate_key)
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # 加密令牌
    local encrypted_token=$(encrypt_token "$token" "$key")
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # 更新配置文件写入
    cat > "$CONFIG_FILE" << EOF
[GENERAL]
# 雷池WAF主机地址和端口
SAFELINE_HOST = $host
SAFELINE_PORT = $port
API_PREFIX = $api_prefix

# IP组名称
HIGH_RISK_IP_GROUP = "$high_risk_ip_group"
LOW_RISK_IP_GROUP = "$low_risk_ip_group"

# 查询间隔(秒)
QUERY_INTERVAL = $query_interval

# 每页查询最大日志数量
MAX_LOGS_PER_QUERY = $max_logs

# 每次查询最大页数
MAX_PAGES_PER_QUERY = $max_pages

# 攻击类型过滤（默认过滤黑名单攻击）
ATTACK_TYPES_FILTER = "-3"

[MAINTENANCE]
# 缓存清理间隔(秒)
CACHE_CLEAN_INTERVAL = 3600

[TYPE_GROUP]
# 高危攻击类型
HIGH_RISK_TYPES = "0,5,7,8,9,11,29"  # SQL注入,后门,代码执行,代码注入,命令注入,文件包含,模板注入

# 低危攻击类型
LOW_RISK_TYPES = "1,2,3,4,6,10,21"   # XSS,CSRF,SSRF,拒绝服务,反序列化,文件上传,扫描器
EOF
    
    chmod 600 "$CONFIG_FILE"
    echo -e "${GREEN}创建主配置文件: $CONFIG_FILE${NC}"
    
    # 创建日志配置文件 (YAML格式)
    cat > "$LOG_CONFIG_FILE" << EOF
# 日志配置文件
log_dir: logs
log_file: info.log
log_level: $log_level
max_size: 10485760
backup_count: 5
log_format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
retention_days: $log_retention_days
clean_interval: 86400
EOF
    
    chmod 600 "$LOG_CONFIG_FILE"
    echo -e "${GREEN}创建日志配置文件: $LOG_CONFIG_FILE${NC}"
    
    return 0
}

# 创建服务
create_service() {
    print_step 4 6 "创建系统服务"
        
    # 预先创建日志目录并设置权限
    mkdir -p "$INSTALL_DIR/logs"
    chown -R root:root "$INSTALL_DIR"
    chmod -R 755 "$INSTALL_DIR"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=SafeLine AutoBlocker
After=network.target
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
User=root
Group=root

# 设置工作目录和环境变量
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=$INSTALL_DIR
Environment=CONFIG_DIR=$CONFIG_DIR

# 设置PID文件
RuntimeDirectory=safeline
PIDFile=/run/safeline/safeline-autoblocker.pid

# 启动主程序
ExecStart=/usr/local/bin/safeline-ab
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}创建服务文件失败${NC}"
        return 1
    fi
    
    echo -e "${GREEN}创建服务文件: $SERVICE_FILE${NC}"
    
    # 重新加载systemd配置
    systemctl daemon-reload
    
    # 启用服务
    systemctl enable safeline-autoblocker
    
    return 0
}

# 启动服务
start_service() {
    print_step 5 6 "启动服务"
    
    # 验证Python脚本
    if ! python3 -m py_compile "$INSTALL_DIR/$MAIN_SCRIPT"; then
        echo -e "${RED}Python脚本语法检查失败${NC}"
        return 1
    fi
    
    # 验证日志配置文件
    if ! python3 -c "import yaml; yaml.safe_load(open('$LOG_CONFIG_FILE'))"; then
        echo -e "${RED}日志配置文件格式错误${NC}"
        return 1
    fi
    
    # 验证其他配置文件是否存在
    if [ ! -f "$CONFIG_FILE" ] || [ ! -f "$KEY_FILE" ] || [ ! -f "$TOKEN_FILE" ]; then
        echo -e "${RED}配置文件不存在${NC}"
        return 1
    fi
    
    # 确保文件所有者为root且权限正确
    chown root:root "$CONFIG_FILE" "$KEY_FILE" "$TOKEN_FILE" "$LOG_CONFIG_FILE"
    chmod 600 "$CONFIG_FILE" "$KEY_FILE" "$TOKEN_FILE" "$LOG_CONFIG_FILE"
    
    systemctl start safeline-autoblocker
    
    # 等待服务启动并多次检查状态
    for i in {1..5}; do
        sleep 2
        if systemctl is-active --quiet safeline-autoblocker; then
            echo -e "${GREEN}服务启动成功${NC}"
            return 0
        fi
    done
    
    echo -e "${RED}服务启动失败，请检查日志获取详细信息${NC}"
    echo "可使用以下命令查看详细错误信息:"
    echo "journalctl -u safeline-autoblocker -n 50"
    return 1
}

# 清理文件（回滚操作）
cleanup_files() {
    echo -e "${YELLOW}正在清理已安装的文件...${NC}"
    
    # 停止服务
    systemctl stop safeline-autoblocker 2>/dev/null
    
    # 等待停止后禁用服务
    sleep 2  
    systemctl disable safeline-autoblocker 2>/dev/null
    
    # 删除服务文件
    [ -f "$SERVICE_FILE" ] && rm -f "$SERVICE_FILE" && systemctl daemon-reload
    
    # 删除软链接
    rm -f /usr/local/bin/safeline-ab

    # 删除配置文件和目录
    [ -d "$CONFIG_DIR" ] && rm -rf "$CONFIG_DIR"
    
    # 删除脚本文件
    [ -d "$INSTALL_DIR" ] && rm -rf "$INSTALL_DIR"
    
    # 尝试删除父目录（如果为空）
    PARENT_DIR=$(dirname "$INSTALL_DIR")
    [ -d "$PARENT_DIR" ] && [ -z "$(ls -A "$PARENT_DIR")" ] && rmdir "$PARENT_DIR"
    
    echo -e "${YELLOW}清理完成，安装已回滚${NC}"
}

# 主函数
main() {
    print_banner
    
    # 检查root权限
    check_root
    
    # 检查依赖
    check_dependencies
    
    # 创建目录
    if ! create_directories; then
        echo -e "${RED}创建目录失败，安装中止${NC}"
        exit 1
    fi
    
    # 下载所有文件
    if ! download_files; then
        echo -e "${RED}下载文件失败，安装中止${NC}"
        cleanup_files
        exit 1
    fi
    
    # 创建配置文件
    if ! create_config; then
        echo -e "${RED}创建配置文件失败，安装中止${NC}"
        cleanup_files
        exit 1
    fi
    
    # 创建服务
    if ! create_service; then
        echo -e "${RED}创建服务失败，安装中止${NC}"
        cleanup_files
        exit 1
    fi
    
    # 启动服务
    if ! start_service; then
        echo -e "${RED}启动服务失败，请检查日志错误信息${NC}"
        exit 1
    fi
    
    # 安装完成
    print_step 6 6 "安装完成"
    echo -e "
    ${GREEN}✓ SafeLine AutoBlocker 已成功安装!${NC}
    
    您可以使用以下命令管理服务:
      启动服务: systemctl start safeline-autoblocker
      停止服务: systemctl stop safeline-autoblocker
      查看状态: systemctl status safeline-autoblocker
      重启服务: systemctl restart safeline-autoblocker
      启用服务: systemctl enable safeline-autoblocker
      禁用服务: systemctl disable safeline-autoblocker
      查看日志: journalctl -u safeline-autoblocker -f
      
    配置文件位置: $CONFIG_FILE
    卸载脚本位置: $INSTALL_DIR/$UNINSTALL_SCRIPT
    "
    
    # 删除安装脚本自身
    echo -e "${BLUE}安装完成，将自动删除安装脚本...${NC}"
    (sleep 1; rm -f "$0") &
}

# 执行主函数
main
