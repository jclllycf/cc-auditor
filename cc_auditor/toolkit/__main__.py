"""python -m cc_auditor.toolkit [--scan]：stdio MCP 或一次原生授权预检。"""
import argparse
import json


def show_result(result):
    """独立 EXE 完成页；只打开本次生成的本地报告，不执行命令或远程 URL。"""
    from pathlib import Path
    from PySide6.QtWidgets import QApplication,QDialog,QVBoxLayout,QLabel,QPushButton,QHBoxLayout
    from PySide6.QtGui import QDesktopServices
    from PySide6.QtCore import QUrl
    app=QApplication.instance() or QApplication([])
    dialog=QDialog();dialog.setWindowTitle('CC Auditor · 预检完成');dialog.resize(650,440)
    layout=QVBoxLayout(dialog);heading=QLabel(result['summary_zh']);heading.setWordWrap(True)
    heading.setStyleSheet('font-size:21px;font-weight:bold;color:#195e63');layout.addWidget(heading)
    for surface,a in result['surface_assessments'].items():
        value=str(a['health_score'])+'/100' if a['health_score'] is not None else '未评分'
        text=QLabel(surface.upper()+'  '+value+' · '+a['recommend_now']+'\n'+a['reason']);text.setWordWrap(True);layout.addWidget(text)
    note=QLabel('健康分越高越好；技术准备与注册/付款资格分开。\n本次待补证 '+str(result['remaining_gap_count'])+' 项。报告仅保存在本机。');note.setWordWrap(True);layout.addWidget(note)
    row=QHBoxLayout();layout.addLayout(row)
    for name,path in result['pdf_paths'].items():
        local=Path(path).resolve()
        button=QPushButton('打开'+name);button.clicked.connect(lambda checked=False,p=local:QDesktopServices.openUrl(QUrl.fromLocalFile(str(p))));row.addWidget(button)
    close=QPushButton('关闭');close.clicked.connect(dialog.accept);layout.addWidget(close);dialog.exec()


def main():
    parser=argparse.ArgumentParser(description='CC Auditor 使用前环境预检');parser.add_argument('--scan',action='store_true');parser.add_argument('--interactive',action='store_true');parser.add_argument('--mcp',action='store_true');parser.add_argument('--pdf-from-report');parser.add_argument('--pdf-v35-from-report')
    args=parser.parse_args()
    if args.pdf_v35_from_report:
        from .pdf_v35 import build
        print(json.dumps(build(args.pdf_v35_from_report),ensure_ascii=False));return 0
    if args.pdf_from_report:
        from .pdf_report_renderer import build_pdf_reports
        print(json.dumps(build_pdf_reports(args.pdf_from_report),ensure_ascii=False));return 0
    if args.scan:
        from .preflight_v3 import prepare,run
        try:result=run(prepare()['scan_id'])
        except PermissionError:
            print(json.dumps({'status':'declined_or_expired','message_zh':'本次未获有效授权，未执行扫描；可重新启动。'},ensure_ascii=False));return 2
        print(json.dumps(result,ensure_ascii=False))
        if args.interactive:show_result(result)
        return 0
    from .mcp_v3 import serve_stdio
    return serve_stdio()
if __name__=='__main__':
    import multiprocessing
    multiprocessing.freeze_support()
    raise SystemExit(main())
