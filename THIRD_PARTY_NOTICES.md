# 许可与第三方组件

本项目自行编写的旋风助手源码、检查脚本和文档采用 [MIT](LICENSE)。该许可不覆盖旋风原引擎、鲨鱼原程序、NNUE、审局库、商标或第三方运行组件。这些内容各自保留原有权利与许可。

## 运行组件

| 组件 | 已确认的信息 | 许可材料 |
| --- | --- | --- |
| Python | 运行包内 `python310.dll` 的版本资源为 3.10.11 | [PSF 及附属许可](licenses/Python-3.10.11-LICENSE.txt) |
| Capstone | 运行包元数据为 5.0.9 | [BSD 许可](licenses/Capstone-5.0.9-LICENSE.txt)，原包的 `_internal/capstone-5.0.9.dist-info/LICENSE.TXT` 同时保留 |
| pefile | Python 运行层使用的 PE 解析依赖 | [MIT](licenses/pefile-LICENSE)；精确打包版本未从现有发行元数据中确认 |
| PyInstaller | Python 运行层的打包工具及引导程序 | [GPLv2-or-later 与打包分发特别例外](licenses/pyinstaller-licenses-COPYING.txt)；精确构建工具版本未从现有发行元数据中确认 |
| Intel SDE / Pin | MAX 预编译运行组件中的执行依赖 | 保留 `RuntimeMAX.zip` 内的 `SDE/Licenses/`，包括 Intel 许可、Pin 许可和第三方声明；不适用本项目 MIT |
| Microsoft 运行库 | 运行包内的 `VCRUNTIME140.dll` 等 Windows 组件 | 遵循其自身许可及分发条件，不适用本项目 MIT |

Python 的许可材料包含其附属组件声明。MAX 运行包中的许可证、PDF 和第三方清单保持原样；本仓库的摘要不替代这些原始条款。三个运行组件的逐文件 SHA-256 清单见 `src/resources/Runtime*Manifest.json`。

`licenses/Capstone-5.0.9-LICENSE.txt` 取自当前运行包，其余列出的许可文本沿用 [鲨鱼启动器项目的许可材料](https://github.com/tippingabke-gif/chessshark-portable-launcher/tree/main/licenses)。它们用于保留许可条件，不证明两个项目的所有依赖版本或构建环境相同。

## 鲨鱼整合包

鲨鱼启动助手源码、构建说明及自身依赖声明见 [已有项目](https://github.com/tippingabke-gif/chessshark-portable-launcher)。整合包内原有的许可证和源码材料继续保留，本次旋风源码目录不重复收录鲨鱼启动器源码。

再分发本项目自行编写的代码时，应保留 MIT 正文及版权声明。再分发第三方组件时，还应保留各组件要求的声明、许可和对应材料；本项目 MIT 不重新许可第三方代码或程序。
