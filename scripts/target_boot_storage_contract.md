# Boot Storage 配额与源码绑定契约

本 phase 保留原 4 个实际随包 BusyBox ash 配额 case，固定 raw exit、完整输出、截止尺寸和内容摘要不变；不执行 boot、Storage dispatch、用户脚本、tar、bzip2、MTD 或服务。

SOURCE_PATHS 为 9 份：mtd_storage.sh、dev_init.sh、reset_ss.sh、rc.c、init.c、rc.h、hook_runner.h、BusyBox shell_common.c 和模板配置。完整函数为 12 个 Storage shell 函数加原 3 个 C 函数，共 15；新增 func_invalidate_hash 和 func_fill。heredoc 内的顶格 `}` 属于生成数据，提取器必须跳过至准确 delimiter，再识别外层闭合 `}`；func_fill 完整 12275 字节，闭 `}` SHA256 为 `8a33754ee43d9d023ad8777d9225e3ffdf69630db8f51ac3a49aa83ddc2b83f8`。

语义固定为：cache 在 save/erase backend 前失效且失败即拒绝；fill 记录原授权、写前撤销，健康 fill 和 tar 验证后仅恢复原有效授权，失败继续拒绝保存；dev_init 保留 load/fill 失败；reset_ss -a 的创建或 chmod 失败传播。新的正向保存授权不由无授权 fill 产生。其余 startup 零参数、30+2+1 秒、128 KiB 流限额及已有 load/restore/reset 准入保持。

三份随包脚本逐字与锁定源匹配并为0755。独立 P 接受器以 AST 只读 B 字面契约，不执行 B/S；实际 TRX map 严格为 BusyBox、mtd_storage.sh、dev_init.sh、reset_ss.sh 四项。BusyBox 的 resolved=bin/busybox 和 mode=0o755 必须先核对，再比较实际 ELF 字节身份；真实解释器和全部库仍独立绑定。

B checker SHA256：`6f227b5c65234163c165ea38c816471b4bd4a957153d0ccdd62acdb4debb63ff`。Storage/dev_init/reset_ss 三源 SHA分别为 `b2e40a853fb308d7b7d773f903c034cf5ab32f67d92ceed542c130ac64f6d017`、`d6bc8c0d7ebc1f0a17fe00cdb1a0752d29899b1b417a3091d851cf5c0369aef9`、`dbe46eb5391499bbf6b88f212ca9420870ce2b0158d5b185cc6fd01ed7edefd8`。完整来源与15函数摘要由 checker 和独立 P 字面期望分别锁定。

上述绑定不证明全机启动、真实 DMA idle、硬件热复位、压力下存活、Flash 原子回滚或 efd2 首跳安全。新 Storage cache13 是单独目标 gate，不改变本 gate 的 quota4。
