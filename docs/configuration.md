# Sing-Box 配置指南

本文档详细介绍了如何配置 Sing-Box 服务。

## 配置文件位置

Sing-Box 的主配置文件位于：
```
/etc/sing-box/config.json
```

## 配置文件结构

配置文件使用 JSON 格式，包含以下主要部分：

```json
{
    "log": {
        "level": "info",
        "output": "/var/log/sing-box.log"
    },
    "inbounds": [],
    "outbounds": [],
    "route": {}
}
```

## 日志配置

可以在配置文件中调整日志级别：

```json
{
    "log": {
        "level": "debug",  // debug, info, warning, error
        "output": "/var/log/sing-box.log",
        "timestamp": true
    }
}
```

## 服务管理

### 查看服务状态
```bash
./deploy-singbox.sh status
```

### 重启服务
```bash
./deploy-singbox.sh restart
```

### 查看实时日志
```bash
tail -f /var/log/sing-box.log
```

## 配置修改后的操作

1. 编辑配置文件：
```bash
nano /etc/sing-box/config.json
```

2. 检查配置文件语法：
```bash
sing-box check -c /etc/sing-box/config.json
```

3. 重启服务使配置生效：
```bash
./deploy-singbox.sh restart
```

## 安全建议

1. 定期检查日志文件中的异常
2. 使用强密码和加密方式
3. 及时更新到最新版本
4. 限制访问IP和端口
5. 配置防火墙规则

## 备份和恢复

### 备份配置
```bash
cp /etc/sing-box/config.json /etc/sing-box/config.json.backup
```

### 恢复配置
```bash
cp /etc/sing-box/config.json.backup /etc/sing-box/config.json
./deploy-singbox.sh restart
```

## 性能优化

1. 调整系统参数：
```bash
# 编辑系统配置
nano /etc/sysctl.conf

# 添加以下参数
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_congestion_control = bbr
```

2. 应用更改：
```bash
sysctl -p
```

## 故障排除

如果服务无法启动或运行异常，请：

1. 检查配置文件语法
2. 查看详细日志
3. 确认端口未被占用
4. 验证系统资源充足

更多故障排除信息，请参考 [故障排除指南](troubleshooting.md)。 