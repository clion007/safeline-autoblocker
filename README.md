# SafeLine AutoBlocker

SafeLine AutoBlocker是一个用于自动识别和封禁恶意IP的Python脚本工具。它通过API监控雷池WAF的安全日志，识别扫描器和攻击行为，并将相应的IP自动添加到不同的IP组（如黑名单或人机验证，可以安装时设置）。

## 功能特点

- 通过API实时监控雷池WAF安全日志
- 自动识别不同的攻击行为
- 支持高危/低危IP分组处理
- 根据攻击类型将IP自动添加到不同的IP组进行拦截
- 支持自定义IP组名称及通过命令行修改
- 支持批量处理IP，提高效率
- 提供完整的安装和卸载脚本
- 提供完整的故障排除文档
- 提供完整的配置文件说明
- 支持安装失败自动回滚
- 自动清理过期日志和缓存
- 完整的日志记录和错误处理
- 支持命令行配置管理
- 支持日志保留时间设置
- 支持日志级别设置
- 优化的进程管理，防止重复运行

## 系统要求

- Python 3.6+
- 雷池WAF (SafeLine WAF)
- Linux系统 (推荐CentOS/Ubuntu)
- systemd 服务管理
- Python依赖包：requests, cryptography

## 安装方法

### 快速安装

使用以下命令安装：

```bash
wget -O - https://gitee.com/clion007/safeline-autoblocker/raw/main/install.sh | sudo bash
```
或者

```bash
curl -sSL https://gitee.com/clion007/safeline-autoblocker/raw/main/install.sh | sudo bash
```

### 手动安装

1. 下载安装脚本：

```bash
wget https://gitee.com/clion007/safeline-autoblocker/raw/main/install.sh -O /tmp/install.sh
```

2. 运行安装脚本：

```bash
sudo chmod +x /tmp/install.sh
sudo python3 /tmp/install.sh
```

3. 按照提示输入雷池WAF的API信息。

## 配置文件说明

配置文件位于 `/etc/safeline/setting.conf`，主要配置项包括：

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| SAFELINE_HOST | 雷池API主机地址 | localhost |
| SAFELINE_PORT | 雷池API端口 | 9443 |
| API_PREFIX | API前缀 | /api/open |
| HIGH_RISK_IP_GROUP | 高危IP组名称 | 黑名单 |
| LOW_RISK_IP_GROUP | 低危IP组名称 | 人机验证 |
| QUERY_INTERVAL | API查询间隔（秒） | 60 |
| MAX_LOGS_PER_QUERY | 每次查询的最大日志数量 | 100 |
| ATTACK_TYPES_FILTER | 攻击类型过滤，多个ID用逗号分隔 | -3 (默认过滤黑名单类型) |
| CACHE_CLEAN_INTERVAL | 缓存清理间隔（秒） | 3600 |
| LOG_CLEAN_INTERVAL | 日志清理间隔（秒） | 86400 |

配置文件还包含 `[TYPE_GROUP_MAPPING]` 部分，用于配置不同攻击类型ID对应的IP组。

日志配置文件位于 `/etc/safeline/log.yaml`，主要配置项包括：

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| LOG_LEVEL | 日志级别 | INFO |
| LOG_RETENTION_DAYS | 日志保留天数 | 30 |
| LOG_FILE | 日志文件路径 | info.log |
| LOG_DIR | 日志目录路径 | logs |
| LOG_FORMAT | 日志格式 | %(asctime)s - %(levelname)s - %(message)s |
| LOG_SIZE | 日志文件大小限制（字节） | 10485760 |
| LOG_BACKUP_COUNT | 日志文件备份数量 | 5 |

## 命令行参数

SafeLine AutoBlocker 支持以下命令行参数：

| 命令 | 说明 | 示例 |
|------|------|------|
| view | 查看当前配置 | `python3 autoblocker.py view` |
| set | 设置配置选项 | `python3 autoblocker.py set SECTION OPTION VALUE` |
| reset | 重置为默认配置 | `python3 autoblocker.py reset --confirm` |
| reload | 重新加载配置文件 | `python3 autoblocker.py reload` |
| version | 显示版本信息 | `python3 autoblocker.py version` |
| log level | 设置日志级别 | `python3 autoblocker.py log level INFO` |
| log retention | 设置日志保留天数 | `python3 autoblocker.py log retention 30` |
| log clean | 清理过期日志文件 | `python3 autoblocker.py log clean` |
| ip-group high-risk | 设置高危IP组名称 | `python3 autoblocker.py ip-group high-risk 黑名单` |
| ip-group low-risk | 设置低危IP组名称 | `python3 autoblocker.py ip-group low-risk 人机验证` |
| ip-group map | 配置攻击类型与IP组的映射 | `python3 autoblocker.py ip-group map 0 high` |

## 使用方法

### 作为服务运行

1. 启动服务：

```bash
sudo systemctl start safeline-autoblocker
```

2. 查看服务状态：

```bash
sudo systemctl status safeline-autoblocker
```

3. 查看日志：

```bash
sudo journalctl -u safeline-autoblocker -f
```
4. 停止服务：

```bash
sudo systemctl stop safeline-autoblocker
```

5. 禁用开机自启：

```bash
sudo systemctl disable safeline-autoblocker
```
6. 启用开机自启：

```bash
sudo systemctl enable safeline-autoblocker
```
7. 重启服务：

```bash
sudo systemctl restart safeline-autoblocker
```

### 手动运行

```bash
sudo python3 /opt/safeline/scripts/autoblocker.py
```

## 攻击类型参考

以下是常见的攻击类型ID及其对应的IP组：

| ID | 攻击类型 | 默认IP组 |
|----|----------|----------|
| 0 | SQL注入 | 黑名单 |
| 1 | XSS攻击 | 人机验证 |
| 2 | 路径遍历 | 人机验证 |
| 3 | 远程文件包含 | 人机验证 |
| 4 | 本地文件包含 | 人机验证 |
| 5 | 远程代码执行 | 黑名单 |
| 6 | PHP代码注入 | 人机验证 |
| 7 | 代码执行 | 黑名单 |
| 8 | 代码注入 | 黑名单 |
| 9 | 命令注入 | 黑名单 |
| 10 | 文件上传 | 人机验证 |
| 11 | 文件包含 | 黑名单 |
| 21 | 扫描器 | 人机验证 |
| 29 | 模板注入 | 黑名单 |

## 卸载方法

### 自动卸载

运行卸载脚本：

```bash
sudo bash /opt/safeline/scripts/uninstall.sh
```

### 手动卸载

1. 停止服务：

```bash
sudo systemctl stop safeline-autoblocker
```

2. 禁用开机自启：

```bash
sudo systemctl disable safeline-autoblocker
```

3. 删除systemd服务文件：

```bash
sudo rm -f /etc/systemd/system/safeline-autoblocker.service
sudo systemctl daemon-reload
```

4. 删除配置文件：

```bash
sudo rm -rf /etc/safeline
```

5. 删除脚本文件：

```bash
sudo rm -rf /opt/safeline
```

## 故障排除

1. 服务无法启动
   
- 检查配置文件是否正确
- 检查API令牌是否有效
- 查看服务日志：`sudo journalctl -u safeline-autoblocker -n 50`

2. 无法添加IP到IP组
   
- 检查API令牌权限
- 确认IP组是否存在于雷池WAF中
- 查看详细日志了解错误原因

3. API连接问题
   
- 确认雷池WAF服务正常运行
- 检查API地址和端口配置
- 确认网络连接正常
- 检查防火墙设置

4. 程序重复运行问题

- 检查PID文件是否存在：`ls -l /var/run/safeline-autoblocker.pid`
- 如果PID文件存在但程序未运行，可以手动删除：`sudo rm /var/run/safeline-autoblocker.pid`

## 常见问题

1. **如何获取雷池API令牌？**
   
登录雷池WAF管理界面，进入"系统设置" -> "API Token"，创建并复制API令牌。

2. **如何查看已封禁的IP？**
   
登录雷池WAF管理界面，进入"防护配置" -> "通用配置" -> "IP组"，查看相应的IP组。

3. **如何修改默认IP组名称？**
   
使用命令行工具修改：
```bash
sudo python3 /opt/safeline/scripts/autoblocker.py ip-group high-risk "黑名单"
sudo python3 /opt/safeline/scripts/autoblocker.py ip-group low-risk "人机验证"
```

4. **如何只监控特定类型的攻击？**
   
编辑配置文件，在 `ATTACK_TYPES_FILTER` 参数中添加攻击类型ID，多个ID用逗号分隔。例如：`ATTACK_TYPES_FILTER = 0,7,9,11,21`

5. **如何增加日志查询频率？**
   
使用命令行工具修改：
```bash
sudo python3 /opt/safeline/scripts/autoblocker.py set GENERAL QUERY_INTERVAL 30
```

6. **如何在雷池WAF中创建IP组？**
   
登录雷池WAF管理界面，进入"安全防护" -> "IP管理"，点击"新建IP组"，创建名为"黑名单"和"人机验证"的IP组，并设置相应的动作。

7. **如何查看程序的运行日志？**
   
程序的日志保存在 `/opt/safeline/scripts/logs/info.log` 文件中，可以使用以下命令查看：
```bash
sudo tail -f /opt/safeline/scripts/logs/info.log
```

8. **如何设置日志保留周期？**
   
使用命令行工具修改：
```bash
sudo python3 /opt/safeline/scripts/autoblocker.py log retention 30
```

9. **如何手动清理过期日志？**
   
可以使用以下命令手动触发日志清理：
```bash
sudo python3 /opt/safeline/scripts/autoblocker.py log clean
```

10. **如何确认程序是否正在运行？**
    
可以使用以下命令检查程序状态：
```bash
sudo systemctl status safeline-autoblocker
```
或者检查PID文件：
```bash
cat /var/run/safeline-autoblocker.pid
```

## 更新日志

### v1.3.0 (2025-04-13)
- 修复已知问题
- 优化PID文件管理，防止程序重复运行
- 改进Linux系统兼容性
- 增强错误处理和日志记录
- 优化资源清理机制
- 优化IP处理逻辑，提高了对攻击的实时响应能力
- 更新配置文件说明，添加CACHE_CLEAN_INTERVAL和LOG_CLEAN_INTERVAL配置项
- 完善故障排除文档，添加程序重复运行问题的解决方案
- 扩展常见问题解答，增加程序运行状态检查方法

### v1.2.0 (2025-04-06)
- 移除日志文件监控功能
- 专注于API监控，提高稳定性
- 优化代码结构
- 添加日志保留时间设置，过期自动删除
- 移除了--api-monitor和--daemon参数，默认以API监控模式运行
- 改进错误处理，提高程序稳定性

### v1.1.0 (2025-04-04)
- 添加攻击类型过滤功能
- 优化日志记录
- 修复已知问题

### v1.0.0 (2025-04-02)
- 初始版本发布
- 支持API监控和日志文件监控
- 支持按攻击类型分配IP到不同IP组

## 许可证

本项目采用MIT许可证。详情请参阅[LICENSE](LICENSE)文件。

## 作者

Clion Nieh - EMAIL: <clion007@126.com>

## 鸣谢

- 雷池WAF团队提供的API支持
