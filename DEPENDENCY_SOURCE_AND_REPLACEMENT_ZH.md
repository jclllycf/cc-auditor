# 对应源码与共享库替换

本程序的 Qt/PySide/Shiboken 共享库保持上游未修改状态，动态放在 `_internal/PySide6`、`_internal/shiboken6`；应用没有校验这些共享库的厂商签名或限制合法替换。中文字体的固定哈希校验与这些共享库无关。

## 对应源码

下列官方源归档已完整下载并按官方 SHA-256 校验。首个公开二进制 Release 必须在同页提供它们，或提供明确、等同且持续可用的下载指引；发行者承担来源持续可取得的责任。仓库中的来源记录不等同于某个尚未创建的 Release 已上传资产。

| 文件 | SHA-256 | 官方下载 |
|---|---|---|
| qtbase-everywhere-src-6.12.0.tar.xz | a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307 | [Qt 官方归档](https://download.qt.io/archive/qt/6.12/6.12.0/submodules/qtbase-everywhere-src-6.12.0.tar.xz) |
| pyside-setup-everywhere-src-6.12.0.tar.xz | 099c1a597cf33c1b000e11cf68a0b82d216fb802bf81726efc720394f10c7751 | [Qt for Python 官方归档](https://download.qt.io/official_releases/QtForPython/pyside6/PySide6-6.12.0-src/pyside-setup-everywhere-src-6.12.0.tar.xz) |

Qt Core/Gui/Widgets/Network、保留的平台/TLS 插件来自 qtbase。公开构建移除 SVG、额外图片格式和软 OpenGL 后端，未以 qtbase 冒充这些已排除模块的源码。PySide 和 Shiboken 源位于同一 pyside-setup 归档。归档含上游构建文件、依赖/编译说明、版权及修改基础。

Python、psutil、PyYAML、pypdf、ReportLab、Pillow 与 charset-normalizer 的对应版本及来源见随包来源记录和各自上游。公开源码包含实际使用的 vendor 源码；ReportLab 的两处本地补丁有明确说明，不声称它们未修改。Windows pyd 为对应 ABI 的二进制，不能据此宣称跨平台源码运行已经验收。

## 在副本中替换 Qt/PySide

1. 完整复制便携目录到新的可写测试目录，保留原始包与报告。关闭这个测试副本的程序。
2. 从上述精确源构建修改版，或使用自行取得且许可兼容的构建。遵循归档内说明和 [Qt 源码构建说明](https://doc.qt.io/qt-6/build-sources.html)、[Qt for Python 构建说明](https://doc.qt.io/qtforpython-6/building_from_source/index.html)。使用 Windows x64、兼容 MSVC/运行库及 CPython ABI；PySide/Qt 模块需要相互匹配。这里没有承诺任意版本都二进制兼容。
3. 把需替换的匹配 DLL/pyd 放入该副本相同路径，保留其依赖。替换 Qt6Core 等底层库时，核对其它 Qt 模块的 ABI；若替换绑定，同时提供匹配的 PySide/Shiboken 运行库。
4. 用该副本执行 `CC_Auditor.exe --mcp` 并由本机 MCP 客户端调用 `audit_capabilities`；验证原生窗口与离线合成 PDF。发生 DLL/符号错误时恢复测试副本中的原文件；不要更改系统 DLL、系统 PATH 或另一应用。

项目不禁止为调试上述共享库修改而进行的逆向工程。库修改可能使原厂签名失效，且其安全、兼容性由修改者自行验证。本说明不是要求普通用户替换库；普通使用完整解压即可。

## 构建本应用

Windows x64、CPython 3.12 虚拟环境中安装 `requirements-build.txt`，然后在全新公开源树运行 `python -B -m public_build.build_windows`。构建器隔离 PATH，并拒绝复用现有 build/dist。离线回归运行 `python -B -m public_build.run_tests`。这验证产品行为，尚不等于位级可重复构建；新 Windows 真机及代理矩阵须另外验收。
