# 第三方组件声明

原创代码：Copyright (c) 2026 jclllycf，MIT。以下组件不因本项目 MIT 许可而改变其原许可。随包 `licenses/` 保存原文、来源及修改通知。

| 组件 | 版本 | 许可 / 说明 |
|---|---|---|
| CPython | 3.12.10 | 完整 PSF 与历史/内含组件条款，见 Python-LICENSE.txt |
| PySide6 Essentials / Shiboken / Qt base | 6.12.0 | 按 LGPL-3.0 分发相应库；保留 LGPL-3.0 和 GPL-3.0 原文、上游附属声明 |
| psutil | 7.2.2 | BSD-3-Clause |
| PyYAML | 6.0.3 | MIT，仅随附纯 Python 加载器 |
| pypdf | 6.10.0 | BSD-3-Clause |
| ReportLab | 4.4.10 | BSD 风格原许可；两处本地安全补丁见 licenses/v34-reportlab-local-patches.md |
| Pillow | 13.0.0 | MIT-CMU 及其内含组件完整许可汇总 |
| charset-normalizer | 3.5.2 | MIT |
| CC Auditor Sans SC | 修改自固定提交的 Noto Sans SC | SIL OFL-1.1；更名、400/700 静态化与字符映射修改见字体 PROVENANCE.json |
| PyInstaller 运行时/引导程序 | 6.22.3 | GPL-2.0-or-later WITH Bootloader-exception；相应运行时文件的 Apache-2.0 声明仍保留 |
| IANA RDAP IPv4 快照 | 2026-10-18 | 上游公开数据；来源、用途与哈希见 rdap_bootstrap_provenance.json |

Qt/PySide 的商业许可指引不是本项目已购买商业授权的证明。本分发采用相应开源许可。应用使用外置共享库；允许为调试库修改所需的逆向工程，不对合法的库替换施加额外限制。对应源码及替换步骤见 [DEPENDENCY_SOURCE_AND_REPLACEMENT_ZH.md](DEPENDENCY_SOURCE_AND_REPLACEMENT_ZH.md)。

`licenses/qtbase-6.12.0/` 与 `licenses/pyside6-6.12.0/` 的通知取自精确官方源归档，保留该版本的版权、归属表和许可全文。包含上游源中的某条通知，不意味着该第三方组件全部被编译进本应用。最终便携包的实际文件及 SHA 以资产清单为准。

本公开包不附带 Microsoft VC 运行库 DLL 或安装程序。缺少运行库的用户从 Microsoft 官方页面单独取得并安装；由系统提供兼容的 x64 运行库。项目没有将 Qt/Python 开源许可误当成 Microsoft 二进制再分发授权。

Qt 图片/SVG 插件、软 OpenGL 后端、旧浏览器 helper 和私人实测数据不属于此公开运行包。
