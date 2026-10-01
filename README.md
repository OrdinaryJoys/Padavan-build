# Padavan K2P 编译

统一编译入口：**Build validated K2P firmware**。构建本账号的 4.4 与 SUSU 源码，按普通 K2P 的实际分区校验镜像，输出源码提交、配置、版本和日志。

详细配置、产物要求和本地编译方法见 [K2P 编译说明](docs/K2P-build.md)。历史工作流保留作参考；新版本使用统一入口。

构建不会刷写路由器。采用 OpenSSL 3.5.9 LTS；升级后的 SSH/VPN 兼容性仍需真机测试。
