#!/bin/bash

# SafeLine AutoBlocker 安装脚本
# 版本: 1.2.0
# 作者: Clion Nieh
# 日期: 2025.4.6
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
KEY_FILE="$CONFIG_DIR/token.key"
TOKEN_FILE="$CONFIG_DIR/token.enc"
CONFIG_EXAMPLE="$CONFIG_DIR/setting.conf.example"
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
    ║       版本: 1.2.0                             ║
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

# 获取用户输入
get_user_input() {
    local prompt=$1
    local default=$2
    local is_password=$3
    local choices=$4
    
    local input_prompt
    
    if [ -n "$default" ]; then
        if [ "$is_password" = "true" ]; then
            input_prompt="$prompt [隐藏]: "
        else
            input_prompt="$prompt [$default]: "
        fi
    else
        input_prompt="$prompt: "
    fi
    
    while true; do
        if [ "$is_password" = "true" ]; then
            read -s -p "$input_prompt" value
            echo
        else
            read -p "$input_prompt" value
        fi
        
        value=$(echo "$value" | xargs) # 去除前后空格
        
        # 使用默认值
        if [ -z "$value" ] && [ -n "$default" ]; then
            echo "$default"
            return 0
        fi
        
        # 验证选择
        if [ -n "$choices" ] && [[ ! "$choices" =~ $(echo "$value" | tr '[:upper:]' '[:lower:]') ]]; then
            echo -e "${YELLOW}请输入有效的选项: $choices${NC}"
            continue
        fi
        
        # 验证非空
        if [ -z "$value" ] && [ -z "$default" ]; then
            echo -e "${YELLOW}此项不能为空，请重新输入${NC}"
            continue
        fi
        
        echo "$value"
        return 0
    done
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
    
    # 安装Python依赖
    echo "安装Python依赖..."
    pip3 install cryptography requests
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
        "logger.py"
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
    done
    
    # 设置执行权限
    chmod 755 "$INSTALL_DIR/$MAIN_SCRIPT"
    chmod 755 "$INSTALL_DIR/$UNINSTALL_SCRIPT"
    
    # 下载配置示例
    echo "正在下载: $CONFIG_EXAMPLE"
    if command -v curl &> /dev/null; then
        curl --fail --silent --location --connect-timeout 15 --retry 3 --output "$CONFIG_EXAMPLE" "$REPO_URL/$CONFIG_EXAMPLE"
    elif command -v wget &> /dev/null; then
        wget --quiet --tries=3 --timeout=15 --output-document="$CONFIG_EXAMPLE" "$REPO_URL/$CONFIG_EXAMPLE"
    else
        echo -e "${RED}错误: 系统中未找到curl或wget${NC}"
        return 1
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}下载配置示例文件失败，安装中止${NC}"
        return 1
    fi
    
    echo -e "${GREEN}所有文件下载完成${NC}"
    return 0
}

# 生成加密密钥
generate_key() {
    # 使用Python生成Fernet密钥
    local key=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    
    if [ -z "$key" ]; then
        echo -e "${RED}生成加密密钥失败${NC}"
        return 1
    fi
    
    # 将密钥保存到文件
    echo "$key" > "$KEY_FILE"
    chmod 600 "$KEY_FILE"
    echo -e "${GREEN}生成加密密钥: $KEY_FILE${NC}"
    return 0
}

# 加密令牌
encrypt_token() {
    local token=$1
    local key=$2
    
    # 使用Python加密令牌
    local encrypted_token=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet('$key'.encode()).encrypt('$token'.encode()).decode())")
    
    if [ -z "$encrypted_token" ]; then
        echo -e "${RED}加密令牌失败${NC}"
        return 1
    fi
    
    # 将加密令牌保存到文件
    echo "$encrypted_token" > "$TOKEN_FILE"
    chmod 600 "$TOKEN_FILE"
    echo -e "${GREEN}创建加密令牌文件: $TOKEN_FILE${NC}"
    
    return 0
}

# 创建配置文件
create_config() {
    print_step 3 6 "配置信息设置"
    echo "请输入以下配置信息:"
    
    local host=$(get_user_input "雷池API地址" "localhost" "false")
    local port=$(get_user_input "雷池API端口" "9443" "false")
    local api_prefix=$(get_user_input "API前缀路径" "/api/open" "false")
    local token=$(get_user_input "雷池API令牌" "" "true")
    local high_risk_ip_group=$(get_user_input "高危攻击IP组名称" "黑名单" "false")
    local low_risk_ip_group=$(get_user_input "低危攻击IP组名称" "人机验证" "false")
    local query_interval=$(get_user_input "API查询间隔（秒）" "60" "false")
    local max_logs=$(get_user_input "每次查询最大日志数量" "100" "false")
    local log_retention_days=$(get_user_input "日志保留天数（0表示永久保留）" "30" "false")
    
    # 日志级别选择
    echo -e "\n请选择日志级别:"
    echo "1) DEBUG - 调试信息（最详细）"
    echo "2) INFO - 一般信息（默认）"
    echo "3) WARNING - 警告信息"
    echo "4) ERROR - 错误信息"
    echo "5) CRITICAL - 严重错误信息（最简略）"
    
    local log_level_choice
    while true; do
        read -p "请输入选项 [1-5] (默认: 2): " log_level_choice
        log_level_choice=${log_level_choice:-2}
        
        case $log_level_choice in
            1) log_level="DEBUG"; break ;;
            2) log_level="INFO"; break ;;
            3) log_level="WARNING"; break ;;
            4) log_level="ERROR"; break ;;
            5) log_level="CRITICAL"; break ;;
            *) echo -e "${YELLOW}无效选项，请重新输入${NC}" ;;
        esac
    done
    
    echo -e "${GREEN}已选择日志级别: $log_level${NC}"
    
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
    
    # 创建主配置文件
    local ip_batch_size=$(get_user_input "批量处理IP数量" "50" "false")
    local ip_batch_interval=$(get_user_input "批量处理间隔（秒）" "300" "false")
    local ip_groups_cache_ttl=$(get_user_input "IP组缓存有效期（秒）" "3600" "false")
    local max_retries=$(get_user_input "API请求最大重试次数" "3" "false")
    
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
    
    # 每次查询最大日志数量
    MAX_LOGS_PER_QUERY = $max_logs
    
    # 攻击类型过滤（默认过滤黑名单攻击）
    ATTACK_TYPES_FILTER = "-3"
    
    # API批量处理配置
    IP_BATCH_SIZE = $ip_batch_size
    IP_BATCH_INTERVAL = $ip_batch_interval
    IP_GROUPS_CACHE_TTL = $ip_groups_cache_ttl
    MAX_RETRIES = $max_retries
    
    [MAINTENANCE]
    # 缓存清理间隔(秒)
    CACHE_CLEAN_INTERVAL = 3600
    
    # 日志清理间隔(秒)
    LOG_CLEAN_INTERVAL = 86400
    
    [TYPE_GROUP]
    # 高危攻击类型
    HIGH_RISK_TYPES = "0,5,7,8,9,11,29"  # SQL注入,后门,代码执行,代码注入,命令注入,文件包含,模板注入
    
    # 低危攻击类型
    LOW_RISK_TYPES = "1,2,3,4,6,10,21"   # XSS,CSRF,SSRF,拒绝服务,反序列化,文件上传,扫描器
    EOF
    
    chmod 600 "$CONFIG_FILE"
    echo -e "${GREEN}创建主配置文件: $CONFIG_FILE${NC}"
    
    # 创建日志配置文件 (YAML格式)
    local LOG_CONFIG_FILE="$CONFIG_DIR/log.yaml"
    cat > "$LOG_CONFIG_FILE" << EOF
    # 日志配置文件
    log_dir: logs
    log_file: erro.log
    log_level: $log_level
    max_size: 10485760
    backup_count: 5
    log_format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    retention_days: $log_retention_days
    EOF
    
    chmod 600 "$LOG_CONFIG_FILE"
    echo -e "${GREEN}创建日志配置文件: $LOG_CONFIG_FILE${NC}"
    
    return 0
}

# 创建服务
create_service() {
    print_step 4 6 "创建系统服务"
    
    cat > "$SERVICE_FILE" << EOF
    [Unit]
    Description=SafeLine AutoBlocker
    After=network.target
    
    [Service]
    Type=simple
    ExecStart=/usr/bin/python3 $INSTALL_DIR/$MAIN_SCRIPT
    Restart=always
    
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
    
    systemctl start safeline-autoblocker
    
    # 检查服务状态
    if systemctl is-active --quiet safeline-autoblocker; then
        echo -e "${GREEN}服务启动成功${NC}"
        return 0
    else
        echo -e "${RED}服务启动失败，请检查日志获取详细信息${NC}"
        echo "可使用命令: journalctl -u safeline-autoblocker -n 50"
        return 1
    fi
}

# 清理文件（回滚操作）
cleanup_files() {
    echo -e "${YELLOW}正在清理已安装的文件...${NC}"
    
    # 禁用服务
    systemctl stop safeline-autoblocker 2>/dev/null
    systemctl disable safeline-autoblocker 2>/dev/null
    
    # 删除服务文件
    [ -f "$SERVICE_FILE" ] && rm -f "$SERVICE_FILE" && systemctl daemon-reload
    
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
        echo -e "${RED}启动服务失败，安装中止${NC}"
        cleanup_files
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