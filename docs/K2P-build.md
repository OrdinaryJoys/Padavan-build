# K2P 固件更新与编译

统一入口是 `.github/workflows/new-build-padavan.yml`（Build validated K2P firmware），生成两个互相独立的版本：

- `k2p-4.4`：OrdinaryJoys/padavan-4.4，适合作为当前 4.4 主路由的候选版本。
- `k2p-susu`：OrdinaryJoys/Padavan-SUSU，3.4 内核的对照版本。编译通过不等于已验证网络行为与 4.4 相同。

`sources.lock.json` 锁定源码提交和工具链校验值。更新源码后，先推送两个源码分支，再更新锁文件并推送本仓库。维护分支的推送会触发编译，也可在 Actions 页面手动运行此流程。仓库若提示 Actions 被禁用，需要启用本仓库的 Actions 后再运行。

## 本次配置

目标为 MT7621、128MB RAM、16MB 闪存的普通 K2P，不是 USB/32MB 改装版。保留源码的板级配置、交换机驱动、VLAN/IPTV 支持和硬件 NAT。4.4 板级配置含 Fullcone NAT；3.4 的具体 NAT 行为仍需设备测试。

加入 SmartDNS、WireGuard、HTTPS 管理支持，并保留 OpenSSH/SFTP、OpenVPN。运行时是否启用这些服务由管理界面及原有设置决定。禁用 Xray、ZeroTier、AdGuardHome、下载器等体积较大的附加程序，避免占满闪存；不超频。

源码更新包括 curl 8.22.0、OpenSSL 3.5.9 LTS、Mozilla CA 证书库、curl 默认 CA 路径、启动时 CA 路径恢复及 DDNS 证书验证。OpenSSH 更新至适配此架构的 9.9p2，OpenVPN 更新至 2.6.23。OpenSSL 使用内置提供者并包含 MIPS 原子运行库；此精简构建不含后量子算法。内核、dnsmasq 等旧组件仍保持原实现；升级后的 TLS 安全默认值及 SSH/VPN 互操作性需要真机测试。

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

目标 OpenSSL 程序另外执行 RSA 2048/SHA-256 临时证书生成及安全级别 2 的验证；临时私钥不会放入产物。新建 OpenVPN 证书默认采用 RSA/DH 2048 位及 SHA-256；已有弱密钥证书如被新 TLS 库拒绝，需要重新签发。新建 SSH 配置不依赖 DSA。OpenVPN 保留 LZO，未编译 LZ4。
