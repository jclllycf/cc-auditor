# v3.7.0-dev1 · 本地开发候选使用说明

这是已接入源码的证据诊断升级，尚未替换或发布 Windows EXE。v3.6 便携包及发行清单保持原状。
开发候选使用 Python **3.12 x64**；项目随附 Pillow 原生扩展不兼容 Python 3.14。真实扫描还需要原项目列明的运行依赖。

## 先看完全离线的可运行演示

双击仓库根目录 `preview-v37.cmd`，或在仓库根目录运行：

```powershell
py -3.12 -m public_build.demo_v37
```

程序不会打开浏览器或发起网络请求；网络 socket 和进程启动在演示中被显式阻断。
它构造两轮标为 synthetic 的报告，保存到新的 `scratch/v37-demo-*/`，打印本地 HTML、JSON、中文双 PDF 与回执路径。
案例包括：业务 DNS 与明确策略不符、修正后的合成对照、另一 Profile 尚未复测、特殊地址、第三方分数失败以及未验收的故障态保护。
这些变化来自合成数据，不是当前电脑的检测或修复结果。

## 解释已有报告，不重新扫描

从仓库根目录运行；将占位路径换成自己的受保护 `evidence.json`：

```powershell
py -3.12 preflight_entry_v3.py --review-report 'D:\AuditResults\after\evidence.json'
py -3.12 preflight_entry_v3.py --review-report 'D:\AuditResults\after\evidence.json' --compare-report 'D:\AuditResults\before\evidence.json'
```

先验证原报告的 schema、SHA-256 和摘要，再新增带内容摘要的只读 HTML/JSON；不覆盖原始文件。
HTML 不包含脚本、远端字体、图片或网页依赖，并设置禁止联网的 CSP。
旧报告缺少新的设备/Profile 绑定时会保留证据缺口，不补造当前通过。

## 本机 Agent / MCP

源码入口仍为 `py -3.12 preflight_entry_v3.py --mcp`，保留七工具名称和原生真人授权。
`audit_capabilities` 现在返回 `version=3.7.0-dev1`、`evidence_contract=3.7.evidence.1` 和 `automatic_remediation_enabled=false`。

原有 `get_preflight_evidence(scan_id)` 不变；新增可选参数：

- `view="diagnostics"`：最多十条脱敏诊断及最多十条只读修复预案，不返回原始 IP/配置。
- `view="comparison", compare_to_scan_id="<前轮32位ID>"`：对比已保存报告，最多返回十行，并列出不可比原因。

仅同一采集器进程中有效的加盐 Profile/设备绑定才可支持比较；重启、不同 Profile、不同版本、不同授权、未知网络意图、不同接收器或失败样本会拒绝或降为部分可比。绑定不是不可伪造的设备认证。
网络样本还要求明确相同的策略与网络上下文；当前默认扫描尚未自动证明这些条件，因此可能正确显示“不能直接比较”。

## 修复预案的状态

目前输出 Problem → Evidence → Change preview → Side effects → Verification → Rollback。
没有实现修复执行器，也不会将 Agent 的一次调用或聊天同意转换成系统写权限。
下一阶段应先实现固定受支持操作、原生二次审批、私密备份校验、当前配置冲突拒绝和离线恢复，然后逐项实机验收。

## 验证与回退

```powershell
py -3.12 -m public_build.run_tests
py -3.12 -m public_build.verify_candidate_v37
py -3.12 -m public_build.verify_product --synthetic-dir scratch/v37-stdio-check
```

开发边界检查只审查明确选中的源码文件；不重写 v3.6 发行清单，不等于新发行验收。
需要回退源码时，在保存自己的未提交工作后切回原 `release/v3.6.0-beta.1` 分支；本轮源码开发没有修改生产环境，无需撤回系统网络设置。
