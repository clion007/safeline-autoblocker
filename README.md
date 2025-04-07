# SafeLine Auto Blocker

## 功能特点

- 通过API实时监控雷池WAF安全日志
- 自动识别扫描器和攻击行为
- 根据攻击类型将IP自动添加到不同的IP组（黑名单或人机验证）
- 支持自定义IP组配置
- 提供完整的安装和卸载脚本
- 支持按攻击类型ID筛选IP
- 支持直接从雷池API获取特定攻击类型的日志

## 系统要求

- Python 3.6+
- 雷池WAF (SafeLine WAF)
- Linux系统 (推荐CentOS/Ubuntu)
- systemd 服务管理
- Python依赖包：requests, cryptography

## 安装方法

### 快速安装

使用以下命令一键安装：

```bash
wget -O - https://gitee.com/clion007/safeline-auto-blocker/raw/main/quick_install.sh | sudo bash
```
或者

```bash
curl -sSL https://gitee.com/clion007/safeline-auto-blocker/raw/main/quick_install.sh | sudo bash
```

### 手动安装

1. 下载安装脚本：

```bash
wget https://gitee.com/clion007/safeline-auto-blocker/raw/main/install_auto_blocker.py -O /tmp/install_auto_blocker.py
```

2. 运行安装脚本：

```bash
sudo chmod +x /tmp/install_auto_blocker.py
sudo python3 /tmp/install_auto_blocker.py
```

3. 按照提示输入雷池WAF的API信息。

## 配置文件说明

配置文件位于 `/etc/safeline/auto_blocker.conf`，主要配置项包括：

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| SAFELINE_HOST | 雷池API主机地址 | localhost |
| SAFELINE_PORT | 雷池API端口 | 9443 |
| SAFELINE_TOKEN_ENCRYPTED | 加密后的API令牌 | (安装时设置) |
| DEFAULT_IP_GROUP | 默认IP组名称 | 人机验证 |
| USE_TYPE_GROUPS | 是否为不同攻击类型使用不同IP组 | true |
| ATTACK_TYPES_FILTER | 攻击类型过滤，多个ID用逗号分隔 | (空，监控所有类型) |
| QUERY_INTERVAL | API查询间隔（秒） | 60 |
| MAX_LOGS_PER_QUERY | 每次查询的最大日志数量 | 100 |
| DEBUG_MODE | 是否启用调试模式 | false |
| LOG_RETENTION_DAYS | 日志保留天数（0表示永久保留） | 30 |

配置文件还包含 `[TYPE_GROUP_MAPPING]` 部分，用于配置不同攻击类型ID对应的IP组：

```ini
[TYPE_GROUP_MAPPING]
# 攻击类型ID到IP组的映射
# 格式: 攻击类型ID = IP组名称
# 高危攻击类型加入黑名单组
0 = 黑名单
5 = 黑名单
7 = 黑名单
8 = 黑名单
9 = 黑名单
11 = 黑名单
29 = 黑名单

# 低危攻击类型加入人机验证组
1 = 人机验证
2 = 人机验证
3 = 人机验证
4 = 人机验证
6 = 人机验证
10 = 人机验证
21 = 人机验证
```

## 命令行参数

SafeLine Auto Blocker 支持以下命令行参数：

| 参数 | 说明 | 示例 |
|------|------|------|
| --list-attack-types | 获取并显示雷池WAF支持的攻击类型 | `python3 safeline_auto_blocker.py --list-attack-types` |
| --get-logs | 获取特定攻击类型的日志 | `python3 safeline_auto_blocker.py --get-logs 0,7,21` |
| --clean-logs | 立即清理过期日志文件 | `python3 safeline_auto_blocker.py --clean-logs` |
| --version | 显示版本信息 | `python3 safeline_auto_blocker.py --version` |
| --help | 显示帮助信息 | `python3 safeline_auto_blocker.py --help` |

## 使用方法

### 作为服务运行

1. 启动服务：

```bash
sudo systemctl start safeline_auto_blocker
```

2. 查看服务状态：

```bash
sudo systemctl status safeline_auto_blocker
```

3. 查看日志：

```bash
sudo journalctl -u safeline_auto_blocker -f
```

### 手动运行

```bash
sudo python3 /opt/safeline/scripts/safeline_auto_blocker.py
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

1. 下载卸载脚本：

```bash
wget https://gitee.com/clion007/safeline-auto-blocker/raw/main/uninstall_auto_blocker.py
```

2. 运行卸载脚本：

```bash
sudo python3 uninstall_auto_blocker.py
```

### 手动卸载

1. 停止服务：

```bash
sudo systemctl stop safeline_auto_blocker
```

2. 禁用开机自启：

```bash
sudo systemctl disable safeline_auto_blocker
```

3. 删除systemd服务文件：

```bash
sudo rm /etc/systemd/system/safeline_auto_blocker.service
sudo systemctl daemon-reload
```

4. 删除配置文件和密钥：

```bash
sudo rm /etc/safeline/auto_blocker.conf
sudo rm /etc/safeline/auto_blocker.key
```

5. 删除脚本文件：

```bash
sudo rm /opt/safeline/scripts/safeline_auto_blocker.py
```

## 故障排除

1. 服务无法启动
   
- 检查配置文件是否正确
- 检查API令牌是否有效
- 查看服务日志：`sudo journalctl -u safeline-auto-blocker -n 50`

2. 无法添加IP到IP组
   
- 检查API令牌权限
- 确认IP组是否存在于雷池WAF中
- 查看详细日志了解错误原因

3. API连接问题
   
- 确认雷池WAF服务正常运行
- 检查API地址和端口配置
- 确认网络连接正常
- 检查防火墙设置

## 常见问题

1. **如何获取雷池API令牌？**
   
登录雷池WAF管理界面，进入"系统设置" -> "API管理"，创建并复制API令牌。

2. **如何查看已封禁的IP？**
   
登录雷池WAF管理界面，进入"安全防护" -> "IP管理"，查看相应的IP组。

3. **如何修改默认IP组名称？**
   
编辑配置文件 `/etc/safeline/auto_blocker.conf`，修改 `DEFAULT_IP_GROUP` 参数，然后重启服务。

4. **如何只监控特定类型的攻击？**
   
编辑配置文件，在 `ATTACK_TYPES_FILTER` 参数中添加攻击类型ID，多个ID用逗号分隔。例如：`ATTACK_TYPES_FILTER = 0,7,9,11,21`

5. **如何增加日志查询频率？**
   
编辑配置文件，减小 `QUERY_INTERVAL` 参数的值（单位为秒）。

6. **如何在雷池WAF中创建IP组？**
   
登录雷池WAF管理界面，进入"安全防护" -> "IP管理"，点击"新建IP组"，创建名为"黑名单"和"人机验证"的IP组，并设置相应的动作。

7. **如何查看程序的运行日志？**
   
程序的日志保存在 `/var/log/safeline/auto_blocker.log` 文件中，可以使用以下命令查看：
```bash
sudo tail -f /var/log/safeline/auto_blocker.log
```

8. **如何设置日志保留周期？**
   
编辑配置文件 `/etc/safeline/auto_blocker.conf`，修改 `LOG_RETENTION_DAYS` 参数的值（单位为天）。设置为0表示永久保留日志。

9. **如何手动清理过期日志？**
   
可以使用以下命令手动触发日志清理：
```bash
sudo python3 /opt/safeline/scripts/safeline_auto_blocker.py --clean-logs
```

## 更新日志

### v1.0.0 (2025-04-02)
- 初始版本发布
- 支持API监控和日志文件监控
- 支持按攻击类型分配IP到不同IP组

### v1.1.0 (2025-04-04)
- 添加攻击类型过滤功能
- 优化日志记录
- 修复已知问题

### v1.2.0 (2025-04-06)
- 移除日志文件监控功能
- 专注于API监控，提高稳定性
- 优化代码结构
- 添加日志保留时间设置，过期自动删除
- 移除了--api-monitor和--daemon参数，默认以API监控模式运行
- 改进错误处理，提高程序稳定性

## 许可证

本项目采用MIT许可证。详情请参阅[LICENSE](LICENSE)文件。

## 作者

Clion Nieh - EMAIL: <clion007@126.com>

## 鸣谢

- 雷池WAF团队提供的API支持
- 咖啡星人k博客文章提供的指导和帮助