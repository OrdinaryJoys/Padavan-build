# Storage 缓存失效目标验证协议

本门禁为 final-only，补充既有 Boot Storage 4 项，不替代或放宽 boot4。协议固定为 **13 case、26 phase**。源 owner 已完成当前接口修复并停止写入；whole/执行片段与 MODEL 摘要按下文登记。目标 MIPS 执行和最终镜像验收仍须由新候选 CI 与独立接受器完成，不能用源适配测试代替。

## 调用与实际执行范围

唯一生产接口为：

```text
--trunk PATH --rootfs PATH --sysroot PATH --image PATH --boot-storage-report PATH --output PATH
```

各参数显式必需；没有 preflight 或镜像目录推断路径。`--sysroot` 对应本次 trunk/romfs 的实际运行库。运行环境只准备普通文件和所需库链接，不复制 `/dev` 或设备节点；输入路径先解析为实际身份，不能把 `/var` 等别名当成不同夹具。

实际执行镜像随包的 MIPS BusyBox ash，以及当前源码的完整 `func_save`、`func_record_hash`、`func_invalidate_hash`、`func_erase`。唯一命令路径重绑定是将源码中的绝对 `/sbin/storage_validate` token 指向 `cache_validator`，后者对成功发布调用同一实际随包 MIPS helper；不替换其实现。whole 函数与执行片段分别锁摘要，并独立核对该重绑定是唯一正文差异。

所有 applet wrapper 显式调用 QEMU、该 BusyBox 和同一运行库，不搜索宿主 PATH，不在目标命令缺失、失败或超时时回退到宿主程序。实际 helper、BusyBox、配置、rootfs 脚本及动态库闭包均须绑定。

所有数据均为严格私有夹具目录中的普通文件。故障只允许普通文件模拟的 `mtd_write` seam，以及固定 MODEL 中列出的缓存失效、hash 暂存/发布和 self-SIGKILL 故障点。不得访问真实 MTD、`/proc`、设备、主机 Storage 或私密备份；不得用泛化失败 stub 掩盖未指定的生产错误。

## 固定 case 与阶段

以下取自 producer 的 literal `CASES`。每个 phase 元组依次为 `(输入标记, 故障, raw_exit, flash状态, cache状态, backend调用数)`。A/B 是 MODEL 固定合成输入及其对应压缩 flash 字节的标记，`partial` 是固定普通文件扰动字节，null 表示缓存不存在；它们不是从运行结果生成的期望。

1. `same-A-skip`：`(A, normal, 0, A, A, 0)`。
2. `changed-B-success-then-skip`：`(B, normal, 0, B, B, 1)`；`(B, normal, 0, B, B, 0)`。
3. `prewrite-invalidate-error`：`(B, invalidate-error, 1, A, A, 0)`。
4. `partial-B-error-then-A`：`(B, write-partial-error, 1, partial, null, 1)`；`(A, normal, 0, A, A, 1)`；`(A, normal, 0, A, A, 0)`。
5. `zero-write-error-then-A`：`(B, write-error, 1, A, null, 1)`；`(A, normal, 0, A, A, 1)`。
6. `kill-before-write-then-A`：`(B, kill-before-write, -9, A, null, 1)`；`(A, normal, 0, A, A, 1)`。
7. `kill-partial-B-then-A`：`(B, kill-partial, -9, partial, null, 1)`；`(A, normal, 0, A, A, 1)`。
8. `kill-complete-B-then-B`：`(B, kill-after-write, -9, B, null, 1)`；`(B, normal, 0, B, B, 1)`。
9. `hash-stage-error-then-B`：`(B, hash-stage-error, 1, B, null, 1)`；`(B, normal, 0, B, B, 1)`。
10. `hash-publish-error-then-A`：`(B, publish-error, 1, B, null, 1)`；`(A, normal, 0, A, A, 1)`。
11. `kill-before-publish-then-A`：`(B, kill-before-publish, -9, B, null, 1)`；`(A, normal, 0, A, A, 1)`。
12. `kill-after-publish-then-B-skip`：`(B, kill-after-publish, -9, B, B, 1)`；`(B, normal, 0, B, B, 0)`。
13. `erase-partial-error-then-A`：`(A, erase-partial-error, 1, partial, null, 1)`；`(A, normal, 0, A, A, 1)`；`(A, normal, 0, A, A, 0)`。

case、phase、顺序、合成字节、故障、退出码、完整 stdout/stderr、事件、cache 和 flash 都属于 canonical JSON literals 的 MODEL，必须按冻结的规范化 JSON 字节锁定 `model_data_sha256`。不能从 report、运行结果或另一构建反推期望。

部分 B 失败后的 A 重写和 A skip 是独立阶段，不能只检查最终 flash。erase 部分失败也必须先使缓存失效，随后 A 必须实际重写，第三阶段才允许 skip。erase 调用分别记录 `function_result` 与 `dispatcher_result`：实际 driver 保留 `RESULT:<值>`、`DISPATCH:<值>` 两行，并以 dispatcher 值退出；不得混淆函数返回和全局 `result`。self-SIGKILL 没有正常尾部输出时，按固定 raw 期望拒绝补造结果。

`func_erase` 的源契约另要求：先调用 `func_invalidate_hash`；失效失败时 `result=1`、返回 1 且不调用 backend；erase 失败保持缓存缺失；成功后的 RAM 清理、重建和 slk 置位均检查返回。本固定 erase case 实际执行部分失败分支；完整函数绑定不能冒充成功 erase 路径也已目标执行。

## 输出、raw 限额与退出码

固定输出为：

- `target-storage-cache.json`：主报告。
- `target-storage-cache.sh`：实际运行脚本。
- `target-storage-cache.stdout.json`：全部 26 phase 的完整原始记录。
- `target-storage-cache-busybox.config`：实际编译配置。

每条 raw phase 为扁平对象，字段固定为：

```text
{case, phase, raw_exit, stdout, stderr, events, cache, flash_base64}
```

`raw_exit` 为严格整数，不接受布尔或字符串。直接被 SIGKILL 终止保留 `-9`，不得改写为 137、1 或成功。stdout/stderr 与事件按实际完整字节记录；`cache` 仅为 JSON null 或字符串；`flash_base64` 严格解码并规范再编码，表示完整模拟 flash 字节。字段类型、事件次序与内容按冻结 MODEL 核对。

固定上限均为字节：每 phase stdout **16,384**、stderr **4,096**、events **16,384**、cache **1,024**、解码后 flash **524,288**；整个 raw JSON **4,194,304（4 MiB）**；单 phase 期限 **20 秒**。达到读取上限后必须检查 EOF，不能截断后接受。超限、超时、未完成进程、重复/缺失/多余 phase、重复 JSON key、无效编码、非有限数、额外 stdout 或诊断不符均拒绝。不得只取最后一行、吞掉前后输出，或以外层成功覆盖阶段失败。

## 主报告与父证明绑定

主报告字段固定为：

```text
schema_version / status / profile / phase / execution_role /
required_cases / checks / source_files / source_sha256 /
function_manifest / model_data_sha256 / rootfs_bindings /
compiled_busybox_config / script / stdout / runtime / qemu /
parent_reference / image_reference / limits
```

结构、严格类型及固定值由冻结 schema/MODEL 决定。`required_cases` 必须是上述 13 项，`checks` 完整表达固定 26 phase；不能信任报告自报总数或 status。script、config、stdout 绑定真实文件名和 SHA；stdout 另绑定尺寸，日志副本须逐字一致。

源码映射包含六份：实际 storage 脚本、`storage_validate.c`、其 `startup_config_publish.h` 和 scripts Makefile，以及 BusyBox 模板和 `shell_common.c`；函数 manifest 包含四个 actual 函数的 whole/执行片段身份。最终源接口或 pin 为 pending 时禁止 PASS。

`runtime` 记录实际 BusyBox、helper、解释器及所需库；rootfs、显式 sysroot 与执行副本的身份必须对应，不能只接受同架构 ELF。`parent_reference` 绑定已经完整通过的 boot4 报告 SHA、固定 4 case、同一源码和镜像、相同 Storage/dev_init 脚本以及 BusyBox/config/runtime 身份；boot4 的既有源码/函数准入和配额判据继续保留；本 phase 的新增源码函数契约以根任务冻结值为准。源码改变时重新锁定最终来源，不能沿用旧 pin 冒充新构建。

`image_reference` 显式绑定 `--image` 的实际固件与 rootfs；同名文件、其他构建的父报告或 caller 参数调换都不得接受。源码、脚本、runtime 和镜像关系须由最终 TRX 的独立提取再核对。

## 独立接受与证明边界

P 独立接受器不调用 B producer、S 生成器或其接受函数。它从冻结 literal MODEL 独立重建脚本与期望，核对 source whole/片段、typed 13/26 结构、完整 raw、输出文件、runtime、父 boot4 和同 image/rootfs 绑定。producer 自报 PASS、最后一行、汇总数或 report 外层 SHA 不能代替语义核对。

本门禁验证实际随包 BusyBox/helper 执行当前四函数时，在固定普通文件故障模型中的缓存失效、重写、跳过和错误传播。合成 save 输入不等于已执行 tar 验证、ready 授权或完整脚本 dispatch。它不执行完整启动、真实 Flash 操作、服务、MTD/proc、硬件复位或历史 efd2 升级链，不证明 Flash 原子性、断电回滚、全机内存、硬件时序或首次 hop 安全；模拟恢复到 A 也不表示设备有自动回滚。

任何源码、MODEL、脚本或固定期望改动，都必须在本 phase 的新候选 artifact 下载前同步锁定并重新验证。旧 sealed 包及其 F149 不修改。

## 当前锁定源与模型摘要

- Storage 全文件 SHA256：`b2e40a853fb308d7b7d773f903c034cf5ab32f67d92ceed542c130ac64f6d017`。
- MODEL literal canonical JSON SHA256：`878cb393937e6b36a95618878cd91cf13183db6ca9db5e5dc4556ac7255ff04e`。
- 完整实际执行脚本 SHA256：`5e9d2915b1463f480264f1747a6024ab601a05cf228230e312cc41aeb7dfc704`。
- whole 函数提取从函数声明至闭合 `}`，不包含其后换行；全部源文件及四函数准确摘要位于 producer 的 literal `EXPECTED_SOURCE_SHA256`、`EXPECTED_FUNCTION_SHA256`。
- `DRIVER_PREFIX` 显式 `umask 077`，使实际 validator 收到生产契约要求的私有 hash 暂存文件；不是放宽 validator。
- 初始 A 是普通文件模型中已完成保存的假设状态；后续成功写入由实际 target bzip2 与实际 helper 完成。模拟恢复到 A 不代表真实 Flash 自动回滚。
