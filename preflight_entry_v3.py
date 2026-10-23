"""Windows 打包入口：双击扫描；--mcp 提供本地非 Claude Agent 的 stdio。"""
if __name__=='__main__':
    import multiprocessing,sys
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8')
    multiprocessing.freeze_support()
    if len(sys.argv)==1:sys.argv.extend(['--scan','--interactive'])
    from cc_auditor.toolkit.__main__ import main
    raise SystemExit(main())
