# Sing-Box 安装指南

本文档详细介绍了如何安装和初始化 Sing-Box。

## 系统要求检查

在安装之前，请确保您的系统满足以下要求：

1. 操作系统：
   - Ubuntu 18.04 或更高版本
   - Debian 10 或更高版本
   - CentOS 7 或更高版本

2. 硬件要求：
   - CPU: 支持 x86_64, aarch64, armv7 架构
   - 内存: 至少 512MB RAM
   - 磁盘空间: 至少 100MB 可用空间

3. 网络要求：
   - 可访问外网
   - 443 端口未被占用
   - 稳定的 DNS 解析

## 安装步骤

### 1. 下载安装脚本

```bash
wget https://raw.githubusercontent.com/YOUR_USERNAME/sing-box-deploy/main/deploy-singbox.sh
chmod +x deploy-singbox.sh
```

### 2. 运行安装脚本

```bash
./deploy-singbox.sh
```

安装过程中，脚本会：
- 检查系统环境
- 安装必要的依赖
- 下载并安装最新版本的 Sing-Box
- 生成配置文件
- 设置系统服务

### 3. 验证安装

安装完成后，可以使用以下命令检查服务状态：

```bash
./deploy-singbox.sh status
```

## 常见问题

### 1. 依赖安装失败

如果遇到依赖安装失败，请尝试：
```bash
# Debian/Ubuntu
apt update && apt upgrade -y

# CentOS
yum update -y
```

### 2. 服务启动失败

检查日志文件：
```bash
tail -f /var/log/sing-box.log
```

### 3. 端口被占用

如果 443 端口被占用，请先停止占用该端口的服务：
```bash
netstat -tuln | grep ":443"
```

## 升级说明

要升级 Sing-Box 到最新版本，只需重新运行安装脚本：

```bash
./deploy-singbox.sh
```

## 卸载说明

如需卸载 Sing-Box，请运行：

```bash
./deploy-singbox.sh uninstall
```

这将完全移除 Sing-Box 及其配置文件。 