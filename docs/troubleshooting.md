# Sing-Box 故障排除指南

本文档提供了常见问题的解决方案和故障排除步骤。

## 常见错误

### 1. 安装失败

#### 症状
- 安装过程中断
- 依赖包安装失败
- 下载文件失败

#### 解决方案
1. 检查网络连接
```bash
ping -c 4 google.com
```

2. 更新系统包
```bash
# Debian/Ubuntu
apt update && apt upgrade -y

# CentOS
yum update -y
```

3. 检查磁盘空间
```bash
df -h
```

### 2. 服务启动失败

#### 症状
- 服务无法启动
- 服务启动后立即停止
- 状态显示 "failed"

#### 解决方案
1. 检查配置文件语法
```bash
sing-box check -c /etc/sing-box/config.json
```

2. 查看详细日志
```bash
journalctl -u sing-box -n 50 --no-pager
```

3. 检查端口占用
```bash
netstat -tuln | grep "443"
```

### 3. 连接问题

#### 症状
- 无法建立连接
- 连接经常断开
- 延迟过高

#### 解决方案
1. 检查防火墙设置
```bash
# 查看防火墙状态
iptables -L

# 允许必要端口
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

2. 检查系统资源
```bash
# 查看内存使用
free -h

# 查看 CPU 负载
top
```

3. 测试网络连接
```bash
# 测试延迟
ping 8.8.8.8

# 查看路由
traceroute google.com
```

## 日志分析

### 查看实时日志
```bash
tail -f /var/log/sing-box.log
```

### 常见日志错误及解决方案

1. "端口已被占用"
```
检查并关闭占用端口的进程：
lsof -i :443
```

2. "配置文件错误"
```
使用配置检查工具验证：
sing-box check -c /etc/sing-box/config.json
```

3. "内存不足"
```
检查并清理系统内存：
sync && echo 3 > /proc/sys/vm/drop_caches
```

## 性能优化

### 1. 系统优化

编辑系统配置：
```bash
nano /etc/sysctl.conf

# 添加以下优化参数
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
```

应用更改：
```bash
sysctl -p
```

### 2. 服务优化

1. 调整日志级别
2. 优化路由规则
3. 合理设置缓存大小

## 安全检查

### 1. 检查系统日志
```bash
grep "Failed password" /var/log/auth.log
```

### 2. 检查服务状态
```bash
systemctl status sing-box
```

### 3. 检查网络连接
```bash
netstat -tupln
```

## 备份和恢复

### 创建备份
```bash
# 备份配置文件
cp /etc/sing-box/config.json /etc/sing-box/config.json.backup

# 备份整个配置目录
tar -czf sing-box-backup.tar.gz /etc/sing-box/
```

### 恢复备份
```bash
# 恢复配置文件
cp /etc/sing-box/config.json.backup /etc/sing-box/config.json

# 恢复整个配置目录
tar -xzf sing-box-backup.tar.gz -C /
```

## 联系支持

如果问题仍然存在：

1. 查看 [GitHub Issues](https://github.com/johnsmith8736/sing-box-deploy/issues)
2. 提交新的 Issue
3. 加入社区讨论组获取帮助 