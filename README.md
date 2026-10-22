# 象棋旋风破解器

适配版本：**10.01 旗舰版**。支持原包中的 **OPT、COM、MAX** 三个引擎，棋盘通过 UCI 加载对应原 EXE。

[下载单独版](https://github.com/tippingabke-gif/cyclone-nn-cracker/releases/latest) · [使用说明](使用说明.md) · [原理说明](原理说明.md) · [界面截图](界面截图.md)

## 下载与启动

单独版适合已有引擎和棋盘的用户。将“象棋旋风破解器.exe”放到三个原引擎与 cyclone-eval.nnue 所在目录，打开助手，启用所需版本，再在棋盘中加载对应原 EXE，协议选择 UCI。计算期间保持助手运行。

鲨鱼象棋整合包正在整理，当前尚未发布解压即用版本。

| 版本 | 棋盘选择的原文件 |
| --- | --- |
| OPT | cyclone-nn-opt.exe |
| COM | cyclone-nn-com.exe |
| MAX | cyclone-nn-opt-max.exe |

## 审局库

**支持使用旋风审局库（残局库）**。在引擎目录的 config.ini 中配置 TB_Path，重新启动引擎后生效。审局库由用户自行准备，未包含在单独版中。OPT 已观察到引擎识别审局库文件；特定局面是否实际查表，需要结合 tbhits 等输出判断。NNUE 模型和审局库是两类不同文件。

## 使用环境

Windows 10/11 x64，完整解压到可写目录。启动时按系统提示确认管理员权限。建议先使用 OPT；需要兼容版本时选择 COM。MAX 已在虚拟机完成加载和计算验证，当前使用兼容执行链，未完成本机原生性能与兼容性验收。

![OPT 计算界面](opt-usage.png)

用户提供的实际使用截图，已裁去标题、群号与开局库来源区域。

![三版本助手](helper.png)

当前助手真实截图，原文件路径已遮盖。截图仅展示对应运行状态。

项目地址：https://github.com/tippingabke-gif
