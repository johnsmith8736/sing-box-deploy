# sing-box 一键自动化安装脚本

## 一键安装/配置/升级

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/johnsmith8736/sing-box/main/deploy-singbox.sh)
```

## 一键卸载

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/johnsmith8736/sing-box/main/deploy-singbox.sh) uninstall
```

## 其他命令
- 查看状态：`./deploy-singbox.sh status`
- 重启服务：`./deploy-singbox.sh restart`
- 卸载：`./deploy-singbox.sh uninstall`

---

## 脚本主要特性
- 一条命令全自动完成 sing-box 的安装、配置、升级、卸载
- 自动检测并安装依赖（bc, jq, curl, dnsutils, openssl 等）
- 自动修复 DNS 问题，保障网络连通
- 自动下载并安装 sing-box 最新 1.11.x 版本
- 自动生成配置参数（UUID、Reality Key、WARP 等）
- 自动解析 WARP 配置，兼容多种格式
- 详细报错和友好提示，自动备份配置和日志
- 支持 systemd 服务管理，自动生成客户端配置信息

## 常见问题与排查建议
- 如遇依赖安装失败，请根据提示手动安装相关依赖
- 如遇 DNS 解析失败，脚本会自动修复 /etc/resolv.conf，若仍失败请检查服务器网络和防火墙
- 如遇端口占用、服务启动失败等，脚本会有详细报错并给出排查建议
- 如遇网络限制（如云厂商封锁 53/443 端口），请联系服务器提供商或检查安全组/防火墙

> 脚本和文档持续更新，欢迎反馈和贡献！