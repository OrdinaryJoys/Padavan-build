# K2P 固件更新与编译

统一入口是 `.github/workflows/new-build-padavan.yml`（Build validated K2P firmware），生成两个互相独立的版本：

- `k2p-4.4`：OrdinaryJoys/padavan-4.4，适合作为当前 4.4 主路由的候选版本。
- `k2p-susu`：OrdinaryJoys/Padavan-SUSU，3.4 内核的对照版本。编译通过不等于已验证网络行为与 4.4 相同。

`sources.lock.json` 锁定源码提交和工具链校验值。更新源码后，先推送两个源码分支，再更新锁文件并推送本仓库。维护分支的推送会触发编译，也可在 Actions 页面手动运行此流程。仓库若提示 Actions 被禁用，需要启用本仓库的 Actions 后再运行。

## 本次配置

目标为 MT7621、128MB RAM、16MB 闪存的普通 K2P，不是 USB/32MB 改装版。保留源码的板级配置、交换机驱动、VLAN/IPTV 支持和硬件 NAT。4.4 板级配置含 Fullcone NAT；3.4 的具体 NAT 行为仍需设备测试。

加入 SmartDNS、WireGuard、HTTPS 管理支持，并保留 OpenSSH/SFTP、OpenVPN。运行时是否启用这些服务由管理界面及原有设置决定。禁用 Xray、ZeroTier、AdGuardHome、下载器等体积较大的附加程序，避免占满闪存；不超频。

源码更新包括 curl 8.22.0、OpenSSL 1.1.1w、Mozilla CA 证书库、curl 默认 CA 路径、启动时 CA 路径恢复及 DDNS 证书验证。OpenSSL 1.1.1w 已停止公开维护，是旧架构的兼容性过渡更新；本次没有把旧内核、dnsmasq、OpenSSH 等组件宣称为最新版。迁移到受维护的 TLS 库需要另外进行兼容性和真机测试。

## 产物验收

只有编译成功、目标程序版本检查及镜像验证全部通过，才上传固件产物。镜像验证覆盖 K2P 标识、Linux/MIPS 类型、内核版本、头部与数据 CRC、SquashFS 位置和实际固件分区上限 **15,925,248 字节**。

固件包包含镜像、SHA256SUMS、源码/工具链来源记录、最终配置、组件版本和镜像验证报告。构建失败时上传诊断记录和日志，流程保持失败状态。

通过这些检查仅代表构建和格式验收成功；不代表已完成 IPTV、硬件 NAT、无线或长期运行测试。本流程不会连接、刷写或重启路由器，也不需要设备密码、DDNS 令牌或配置备份。

## Ubuntu 22.04 本地编译

安装 workflow 中列出的依赖后，在本仓库目录运行：

```sh
bash scripts/build_k2p.sh k2p-4.4
# 或
bash scripts/build_k2p.sh k2p-susu
```

每次编译使用一个干净的目录。镜像保存在 `dist/`，诊断信息保存在 `diagnostics/`。Windows 用于更新和推送仓库，固件构建在 Linux 中进行。
