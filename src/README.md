# 象棋旋风破解器：助手源码

对应 10.01 旗舰版三版本助手，程序集版本 `4.0.6.0`。

本目录包含本项目旋风助手的 C# 控制器与 Python 运行层源码。鲨鱼启动器源码已在 [鲨鱼启动器仓库](https://github.com/tippingabke-gif/chessshark-portable-launcher)发布，本包不重复收录。旋风和鲨鱼原程序本体没有提供源码，本包不包含其原始源码。

## 文件结构

- `controller/`：助手界面、三个版本的会话管理、MAX 生命周期与管道桥接源码。
- `runtime/opt/`、`runtime/com/`：对应版本的 Python 运行层和网络组件源码。
- `runtime/max/`：MAX 工作进程、调试协议客户端、管道通信和进程辅助源码。
- `resources/`：原发行助手使用的预编译运行组件 ZIP 及逐文件哈希清单。
- `BUILD.md`：构建步骤和依赖说明。
- `SHA256SUMS.txt`：源码包的文件校验值。

GitHub 的 `src/` 展示源码与组件清单。完整离线源码包额外携带三个预编译运行组件。

## COM r5 目录修复

COM 的日志目录取自 `CYCLONE_RUNTIME_ROOT`；未设置时使用模块目录，并自动创建父目录。附带的 RuntimeCOM.zip、manifest 与 Python 源码同步更新。OPT/MAX 资源与控制器沿用原包。

## 对应版本

COM r5 修订助手的 SHA-256：

```text
dfc745fa03f5ff02a7ca9ab82be608c022882c00d217a4703f048ba37a69acae
```

运行组件按最终构建清单逐文件核验。源码来自该构建的控制器和运行层文件；本次整理未重新执行引擎，也未进行整包运行验收。不同编译器、依赖版本、压缩工具及 PE 时间戳会影响重新构建文件的哈希。

第三方组件保留各自许可证。Intel SDE 等外部组件以原有二进制形式随运行资源提供，其实现源码不属于本项目。

项目地址：https://github.com/tippingabke-gif
# 象棋旋风破解器：助手源码

对应 10.01 旗舰版三版本助手，程序集版本 `4.0.6.0`。

本目录包含本项目旋风助手的 C# 控制器与 Python 运行层源码。鲨鱼启动器源码已在 [鲨鱼启动器仓库](https://github.com/tippingabke-gif/chessshark-portable-launcher)发布，本包不重复收录。旋风和鲨鱼原程序本体没有提供源码，本包不包含其原始源码。

## 文件结构

- `controller/`：助手界面、三个版本的会话管理、MAX 生命周期与管道桥接源码。
- `runtime/opt/`、`runtime/com/`：对应版本的 Python 运行层和网络组件源码。
- `runtime/max/`：MAX 工作进程、调试协议客户端、管道通信和进程辅助源码。
- `resources/`：原发行助手使用的预编译运行组件 ZIP 及逐文件哈希清单。
- `BUILD.md`：构建步骤和依赖说明。
- `SHA256SUMS.txt`：源码包的文件校验值。

GitHub 的 `src/` 展示源码与组件清单。完整离线源码包额外携带三个预编译运行组件。

## 对应版本

原发行助手的 SHA-256：

```text
4a3fe0a440a6b54a08fe4ca8a96bfb020b6cecbb3ae33e1e9526893d5face079
```

运行组件按最终构建清单逐文件核验。源码来自该构建的控制器和运行层文件；本次整理未重新执行引擎，也未进行整包运行验收。不同编译器、依赖版本、压缩工具及 PE 时间戳会影响重新构建文件的哈希。

第三方组件保留各自许可证。Intel SDE 等外部组件以原有二进制形式随运行资源提供，其实现源码不属于本项目。

项目地址：https://github.com/tippingabke-gif
