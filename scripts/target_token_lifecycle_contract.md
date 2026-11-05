# Current token / SER / KTHREAD ownership contract

This gate executes 50 fixed current cases in three inert static MIPS userspace probes: token18, SER25 and task7. It never loads a module, creates a kernel task, opens a device, performs DMA, connects to a router or writes firmware.

The source manifest contains 17 complete function entries, with 16 distinct functions because `__RtmpOSTaskKill` is retained in both the SER and task probes. Token binds six functions; SER binds eight; task ownership binds three. The actual token structures, SER state/owner declarations, task states, NDIS status values, HALT flag and SER wire constants are read or checked against the locked source headers. Source-only checks also bind close/HwCtrlExit retirement order, normal reopen order and Linux4.4 `kthread_stop` semantics.

Tasklet selection is established by the MT7615 chip capabilities. `CONFIG_PROPRIETARY_DRIVER` is not a required MT7615 compiler flag; its active unconditional definition belongs to another chipset branch.

The source harnesses are parsed as literal data. The gate never imports or calls a source harness generator. Current model hashes are:

- token: `0534395867ebdd22df8da5ef3a24cf1cc294aef0509657c92c5aca34462079bf`
- SER: `93e02e20f176ec51464a8d504d8928f26060af3bfb578b077366043a150ce355`
- task: `ad676332c4a063f113719791b0c96e9fc4e30e64cfa965996f2640f4cac2b000`

Run the early check with `--trunk PATH --compiler PATH --output PATH/target-token-lifecycle.json --preflight`. Run the final check with the same three arguments and `--wifi-report PATH/target-wifi-factory.json`, omitting `--preflight`. The modes are exclusive. The final mode requires the completed same-source/configuration Factory49 module/image parent and its four existing exports. A separate independent verifier must validate that parent and its actual image identity.

The report exposes `schema_version`, `status`, `profile`, `phase`, `execution_role`, `required_cases`, `checks`, `source_files`, `source_sha256`, `component_models`, `source_contract`, `function_manifest`, `probes`, `compiled_binding`, `compiler` and `limits`. Every case has exact typed inputs/observations; each complete stdout JSON line is separately exported. Preflight phase is `early-source-only` with a null compiled binding. Final phase is `final-module-reference-bound`.

Nine probe files are emitted: `target-token-lifecycle-{token,ser,task}-current`, each with `.c` and `.stdout.json` companions. Final mode additionally emits exactly 16 object/command files, `.o` and `.cmd` for labels `token`, `hif`, `hardware`, `recovery`, `basic`, `command`, `os` and `close`. These bind the actual `cut_through`, `rtmp_init`, `hw_init`, `hw_ctrl`, `hw_ctrl_basic`, `hw_ctrl_cmd`, `rt_linux` and `rtmp_init_inf` objects. A missing or extra export is rejected. All names use the token lifecycle prefix and do not alter RX/PCI inventories.

`compiled_binding` exposes status, Factory report hash/cases, image hash, built/shipped module hashes, parent/compiled export hashes and each actual object/command/symbol record. Required symbols include token init/deinit, HIF init, recovery, SER init/exit/worker, HwCtrlExit, recovery event producer, public task init/attach/kill wrappers and RTMPDrvClose. Source/command/object/module evidence does not independently replay compilation, linking or relocations.

The concurrency contract has one serialized lifecycle teardown owner racing a SER worker and its producer. It does not cover simultaneous independent teardown owners, non-KTHREAD or OS_ABL variants, other queue-management algorithms or the target kernel callback ABI. Private allocator, pthread, reference and lock recorders model software ownership only. The new source takes a task reference before publication/wake and releases it after stop, including natural early exit; no kernel task is executed by the probes.

Checked DMA/queue APIs are stubbed in this gate; the separate init/DMA gate binds the implementation and first-arm error chain. The complementary init/DMA gate exercises full-owner terminal containment, command publication and VIF failure paths. Actual hardware drain/hot reset, global memory pressure, efd2 first-hop safety and historical outage attribution remain outside this proof. The inherited twenty-two SER rows remain, with three additional owner-busy/stopping/unpinned wrapper cases; the wrapper uses a nonblocking lifecycle mutex acquisition so a close joining its worker cannot deadlock on that mutex. Passing this gate authorizes no deployment or device operation.
