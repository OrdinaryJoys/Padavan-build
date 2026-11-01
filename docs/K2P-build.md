# K2P 固件更新与编译

统一入口是 `.github/workflows/new-build-padavan.yml`（Build validated K2P firmware），生成两个互相独立的版本：

- `k2p-4.4`：OrdinaryJoys/padavan-4.4，适合作为当前 4.4 主路由的候选版本。
- `k2p-susu`：OrdinaryJoys/Padavan-SUSU，3.4 内核的对照版本。编译通过不等于已验证网络行为与 4.4 相同。

`sources.lock.json` 锁定源码提交和工具链校验值。更新源码后，先推送对应源码分支，用 `git ls-remote` 核对远端提交，再更新对应来源锁并推送本仓库。工作流列出的维护分支推送会触发编译；其他分支需手动运行，并选择待验证的固件版本。仓库若提示 Actions 被禁用，需要启用本仓库的 Actions 后再运行。

## 本次配置

目标为 MT7621、128MB RAM、16MB 闪存的普通 K2P，不是 USB/32MB 改装版。保留源码的板级配置、交换机驱动、VLAN/IPTV 支持和硬件 NAT。4.4 板级配置含 Fullcone NAT；3.4 的具体 NAT 行为仍需设备测试。

加入 SmartDNS、WireGuard、HTTPS 管理支持，并保留 OpenSSH/SFTP、OpenVPN。运行时是否启用这些服务由管理界面及原有设置决定。禁用 Xray、ZeroTier、AdGuardHome、下载器等体积较大的附加程序，避免占满闪存；不超频。

源码更新包括 curl 8.23.0、OpenSSL 3.5.9 LTS、Mozilla CA 证书库、curl 默认 CA 路径、启动时 CA 路径恢复及 DDNS 证书验证。OpenSSH 更新至适配此架构的 10.6p1（同时安装 `sshd-session` 与 `sshd-auth`），OpenVPN 更新至 2.6.23，WireGuard 工具更新至 1.0.20260223。OpenSSL 使用内置提供者并包含 MIPS 原子运行库；此精简构建不含后量子算法。

**本版针对性修复（2026-10-18）：**

- **UPnP/DSCP 修复（运行期）**：`xt_DSCP` 在这颗内核上是可加载模块，而设备上没有任何环节在开机时加载它，`miniupnpd` 每次写 `-j DSCP` 都被内核以 ENOENT 拒绝（`iptc_commit() ... No chain/target/match by that name`，实测 390 次/14 天），映射规则只写入一半。现在 `start_upnp()` 在启动 `miniupnpd` 前执行 `modprobe xt_DSCP`，UPnP 行为不变、报错消失。曾尝试把 target 编进内核，但 CI 内核仍按模块编译（`.config` 生效路径待查），因此采用确定性的运行期加载。
- **加密套件说明（不涉及编译开关）**：MT7621 无 AES 指令，实测 ChaCha20-Poly1305 32.9 MB/s、AES-256-GCM 8.8 MB/s（约 3.7 倍）。OpenSSL 3.x 已不存在 `OPENSSL_PREFER_CHACHA_OVER_GCM` 宏（构建期无法改变顺序），偏好由各服务自行决定：管理页 `https_clist` 默认以 `ECDH+CHACHA20` 开头，OpenSSH 默认首选 `chacha20-poly1305@openssh.com`，OpenVPN 在启用时应配置 `data-ciphers CHACHA20-POLY1305`。
- curl 8.22.0 → 8.23.0；WireGuard 工具 1.0.20210914 → 1.0.20260223，下载均校验 SHA256。

构建门禁新增：OpenSSH 版本必须为 10.6p1 且镜像内含 `sshd-auth`；镜像内必须存在 `xt_DSCP.ko` 且源码在启动 UPnP 前 `modprobe xt_DSCP`；`wg --version` 必须为 1.0.20260223；解包镜像后必须能列出 SquashFS 内容，且 `openvpn-cert.sh`、`sshd-session`、`ca-certificates.crt` 存在、`openvpn-cert.sh` 具可执行位。

当前锁定源码已将 dnsmasq 升至 2.93、zlib 升至 1.3.2，并对 miniupnpd、pppd 和内核启动配置做针对性回补；其余内嵌组件仍需分别核实补丁与可达路径。升级后的 TLS 安全默认值及 SSH/VPN 互操作性需要真机测试。

## 产物验收

只有编译成功、目标程序版本检查及镜像验证全部通过，才上传固件产物。镜像验证覆盖 K2P 标识、Linux/MIPS 类型、内核版本、头部与数据 CRC、SquashFS 位置和实际固件分区上限 **15,925,248 字节**。

固件包包含镜像、SHA256SUMS、源码/工具链来源记录、最终配置、组件版本和镜像验证报告。构建失败时上传诊断记录和日志，流程保持失败状态。

通过这些检查仅代表构建和格式验收成功；不代表已完成 IPTV、硬件 NAT、无线或长期运行测试。本流程不会连接、刷写或重启路由器，也不需要设备密码、DDNS 令牌或配置备份。

2026-10-30 补充的镜像内容门禁会从压缩产物批量读取所有普通文件，拒绝不可读的数据块、重复路径，以及必需启动路径中的断链、循环链接或越出镜像根目录的链接。`/init` 的实际内容必须与 `/sbin/rc` 相同；认证与加密程序必须非空且可执行；CA 证书必须从镜像回读并匹配固定 SHA256。合法硬链接会共享 inode，不能仅凭 inode 重复认定镜像损坏。验证器不会在宿主机解包设备节点或建立镜像中的符号链接。

当前候选还要求镜像包含可执行的 `/sbin/storage_validate`，并在编译前运行所锁定源码自带的宿主回归测试。旧 r14 镜像没有此新增工具，会被当前候选门禁拒绝；这与它通过旧阶段检查的结果不同。

4.4 候选的关机 hook 统一通过有界执行器运行：单调时钟 30 秒，随后最多 2 秒 TERM、1 秒 KILL 清理，每条输出流最多 128 KiB。升级前 hook 失败会在停止核心服务之前中止；普通关机则记录失败并继续原关机流程。退出为 0 但仍留有活动后台子进程也视为失败，避免把未完成的配置写入当作成功。执行器不构成 root 脚本沙箱，脱离进程组的特权进程、不可中断内核 I/O 和硬件停滞不受此保证覆盖。

动态 DNS 启动配置由解析器展开一次，封存普通指令、原始来源图和 SHA256；第二次校验及受管理的实际启动复用同一份快照。来源文件、目录成员、票据或快照改变时拒绝启动，不再次执行生成器。按 inode 去重后未再次展开的 include 别名也要核对其路径身份和 SHA256；同一路径可复用已有记录。启动入口为 `dnsmasq.sh --launch`；无参数仅准备和验证配置。受管理的启动解析拒绝前台运行选项及需要解析的上游主机名，应使用数值 IP。运行期 hosts、servers、租约文件仍是动态输入；封存成功和 daemon 启动握手都不等于服务已就绪。

完整构建之前还要通过静态 MIPS 检查：关机执行器的 20 个控制分支（含一次实际 30 秒超时）、完整 DNS 源码编译及快照正反控制、定时器启用和禁用两个可选组件配置。关机探针运行真实 MIPS 执行器和 Linux `/proc`，脚本使用宿主 POSIX shell 夹具，未执行设备 hook。完整构建后另用镜像中的实际 DNS、BusyBox ash、Storage 发布器及目标 libc，在独立 PID、挂载和网络命名空间执行快照与启动检查；只开放私有 loopback UDP，实查首次生成策略的 DNS 答复，并在启动快照清理后再次查询。目标检查与固件、日志两份产物一并保留。

看门狗恢复 DNS 与定时订阅更新改为排队处理，避免在喂狗回调中同步等待配置生成或网络更新；定时更新用单调时钟去重，删除原有阻塞 70 秒的睡眠。定时规则按 7 位星期掩码及 HHMM 分别校验。这些检查不证明实际看门狗设备、无线、IPTV 或长期运行已验收。

来源记录将 Git 提交明确标为基线版本，同时记录源码与构建工具工作区的 dirty 状态、状态列表、已跟踪文件差异的 SHA256，以及最终 `.config` 哈希；两份差异文件也随产物保存。验证成功后重新采集一次，避免用 HEAD 冒充实际修改过的工作区。未跟踪输入会标记 dirty，但其内容不包含在 tracked diff 中，因此 dirty 构建不能仅靠提交号声称可完全重现。

2026-11-01 的 4.4 升级事务门禁覆盖 PID1、Web、GPIO 和 CLI。第一次保存 Storage 之前先取得非阻塞排他锁并建立禁止标记；受支持的管理修改在完整同步操作期间持共享锁，避免检查标记后继续修改的竞态。Web 上传完成后必须先释放共享锁，再通知 PID1，普通只读请求保留。PID1 的信号处理只检查内存状态：升级期间拒绝 TERM/QUIT，其他致命信号进入无日志、无文件访问的等待；未知写入结果或复位系统调用返回后不再恢复延迟热插拔或控制台工作。只有明确写前中止才解除禁止并恢复服务。

新增检查在完整编译前后各执行一次实际源码的 MIPS 跨模块夹具；MTD、看门狗、服务、信号发送和复位均使用无副作用边界。最终检查同时核对镜像 staging 中 rc 与 libshared 的 ELF 和各自的立即绑定标记，下载后还要与压缩镜像的实际字节核对。各自的立即绑定不等于 libc 的全部依赖递归绑定；mlockall 成功不等于所有页面在内存压力下均可用，也不能证明内核、MT7621 或 Bootloader 的物理复位。单 bank 的部分写入无法自动回滚，未知状态不会自动重新写入或重启。

目标运行验证还会用同一工具链编译 ABI 探针，在 QEMU 中配合镜像实际 libc 检查 openat/fstatat/fdopendir/unlinkat、NOFOLLOW 和 CLOEXEC。镜像中的 `/sbin/storage_validate` 与 BusyBox tar 另执行普通、隐藏文件、GNU 长路径和内部链接夹具，逐字节核对恢复内容；截断、未支持的 PAX、超长组件和非目录父项必须被目标校验器拒绝。所有写入都限制在新建的宿主临时目录，不调用闪存、路由器服务或网络。

2026-10-30候选更改了无效自定义DNS/SSH配置的处理：保留原件、明确报错并停止该服务启动，不再静默生成可能更宽松的默认策略。受支持的旧DNS/DSA语法先迁移到候选文件，校验通过且迁移前备份成功后才安装；仅首次缺失的SSH配置可生成并校验默认文件。因此错误的用户配置可能需要通过Web、现有会话或本地控制台修正，升级前应确认配置有效。这是策略保真与服务可用性之间的明确取舍。

HTTP管理的状态变更请求现要求同源浏览器上下文；没有Origin/Referer等来源信息的CLI或自动化写请求，需要显式添加 `X-K2P-Request: 1`，仍须通过原有认证。此约束也覆盖GET触发的修改动作，普通只读页面/已核对的只读RPC保留兼容。握手及请求头总预算30秒；认证及来源校验通过后，应用I/O总预算900秒，单次空闲60秒，适用于上传和GET备份下载。超时不刷新总预算。备份在成功发送200头之前生成并验收，失败返回500，HEAD也会清理临时备份。

miniupnpd在原有每请求64KiB头/1MiB正文上限之外，将HTTP连接数限制为32、请求/响应缓冲容量合计限制为4MiB（包括移动realloc时的新旧峰值预留）。连接绝对时限30秒、无成功I/O空闲时限10秒。它们是局部资源边界，不代表整个路由器RSS或吞吐的上限/提升比例。

可以独立复核已有产物，无需重新编译：

```sh
python3 scripts/test_validate_firmware.py
python3 scripts/validate_firmware.py K2P-image.trx --kernel 4.4 \
  --rootfs-check --output image-validation.json
```

`--rootfs-check` 需要 `unsquashfs`；镜像负向测试还需要 `mksquashfs`。缺少这些工具时，压缩镜像测试会明确显示跳过；CI 在测试前安装 `squashfs-tools`，因此会执行这些测试。

## Ubuntu 22.04 本地编译

安装 workflow 中列出的依赖后，在本仓库目录运行：

```sh
bash scripts/build_k2p.sh k2p-4.4
# 或
bash scripts/build_k2p.sh k2p-susu
```

每次编译使用一个干净的目录。镜像保存在 `dist/`，诊断信息保存在 `diagnostics/`。Windows 用于更新和推送仓库，固件构建在 Linux 中进行。

目标 OpenSSL 程序另外执行 RSA 2048/SHA-256 临时证书生成及安全级别 2 的验证；临时私钥不会放入产物。新建 OpenVPN 证书默认采用 RSA/DH 2048 位及 SHA-256；已有弱密钥证书如被新 TLS 库拒绝，需要重新签发。新建 SSH 配置不依赖 DSA。OpenVPN 保留 LZO，未编译 LZ4。
