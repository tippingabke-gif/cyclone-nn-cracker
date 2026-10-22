# 源码检查与验证范围

[Windows source and compilation checks](https://github.com/tippingabke-gif/cyclone-nn-cracker/actions/workflows/ci.yml) 在推送、拉取请求或手动触发时运行。

## 自动检查内容

1. 用 Python 3.10 解析运行层源码语法，不导入或执行这些模块。
2. 检查三个运行组件清单的路径、重复项及 SHA-256 字段格式。
3. 在 Windows 上编译 C# 控制器，以及 OPT、COM、MAX 网络组件和 MAX 管道桥接组件。

C# 编译检查不嵌入运行组件 ZIP，生成的 `.ci.exe` 仅用于确认源码可以编译。工作流不执行这些输出，不启动棋盘或引擎，也不修改注册表或防火墙。它不创建 Release，不上传程序包。

工作流显示成功，表示该次提交通过了以上检查。此结果不代表完整发行包已重建、实际运行正常、棋力等价、无恶意软件或通过 GitHub 的安全认证。完整助手构建步骤见 [BUILD.md](../src/BUILD.md)。

## MIT 与检查结果

[MIT](../LICENSE) 说明本项目自行编写代码和文档的使用、修改及分发许可。GitHub 识别出 MIT，仅表示识别了许可证。第三方程序与依赖的范围见 [第三方声明](../THIRD_PARTY_NOTICES.md)。

Actions 的检查结果与 MIT 许可是两项独立信息。检查结论应以对应提交的实际工作流结果为准。
