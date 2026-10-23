# CC Auditor 的 ReportLab 4.4.10 限定补丁

原版来自 PyPI 4.4.10，原许可证保留。2026-10-21 对以下两份源码作有意修改：

- `reportlab/__init__.py`：停用 `reportlab.local_rl_mods`、`reportlab_mods.py`、`~/.reportlab_mods` 的动态导入/执行。
- `reportlab/rl_config.py`：仅使用随库默认设置；停用工作目录和用户目录的 Python 设置、`RL_*` 环境覆盖；字体/CMap 搜索路径与可信 URL 范围置空。报告只加载工具自带且核对哈希的字体。

理由：这些可执行的本地定制文件不属于用户授权的诊断资料。成熟库的可扩展默认值不能扩大扫描器的读取/执行边界。渲染器只接收已转义的本地文本和受控表格，不支持外部图片、链接资源或脚本。

上游 `dist-info/RECORD` 保留为原始轮包记录，不能据此声称这两份文件未改动。当前实际 Python 源码由 CC Auditor 的 source_build SHA-256 另行覆盖。Pillow 和 charset-normalizer 未作源码修改。此补丁应在升级依赖时重新检查，并由禁止用户定制代码执行的回归测试保护。
