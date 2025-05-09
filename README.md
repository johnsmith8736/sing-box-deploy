# Sing-Box 自动部署脚本

这是一个用于自动部署和管理 Sing-Box 的 Bash 脚本。该脚本提供了简单的命令行界面，可以轻松地安装、配置和管理 Sing-Box 服务。

## 功能特点

- 自动检测系统环境和依赖
- 支持多种 CPU 架构 (x86_64, aarch64, armv7)
- 自动安装必要的依赖包
- 完整的错误处理和日志记录
- 支持服务状态管理
- 智能的网络环境检测

## 系统要求

- 支持的操作系统：Ubuntu、Debian、CentOS
- 需要 root 权限
- 最小内存要求：512MB
- 最小磁盘空间：100MB

## 快速开始

1. 下载脚本：
```bash
wget https://raw.githubusercontent.com/YOUR_USERNAME/sing-box-deploy/main/deploy-singbox.sh
```

2. 添加执行权限：
```bash
chmod +x deploy-singbox.sh
```

3. 运行脚本：
```bash
./deploy-singbox.sh
```

## 使用方法

```bash
./deploy-singbox.sh [命令]
```

可用命令：
- 无参数     - 安装或更新 sing-box
- status     - 查看服务状态
- restart    - 重启服务
- uninstall  - 卸载 sing-box

## 配置文件位置

- 配置文件：`/etc/sing-box/config.json`
- 日志文件：`/var/log/sing-box.log`

## 详细文档

- [安装指南](docs/installation.md)
- [配置指南](docs/configuration.md)
- [故障排除](docs/troubleshooting.md)

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License

## 免责声明

本项目仅供学习和研究使用，请遵守当地法律法规。作者不对使用本脚本导致的任何问题负责。 