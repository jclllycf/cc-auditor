"""只运行随公共源树提供的离线测试；不探测使用者环境。"""
import os,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    os.chdir(ROOT)
    (ROOT/'scratch').mkdir(exist_ok=True)
    suite=unittest.TestSuite()
    suite.addTests(unittest.defaultTestLoader.discover(str(ROOT/'tests_toolkit'),pattern='test_v*.py',top_level_dir=str(ROOT)))
    suite.addTests(unittest.defaultTestLoader.discover(str(ROOT/'public_build'),pattern='test_*.py',top_level_dir=str(ROOT)))
    result=unittest.TextTestRunner(verbosity=1).run(suite)
    print('Public offline tests:',result.testsRun,'; failures:',len(result.failures),'; errors:',len(result.errors))
    return 0 if result.wasSuccessful() else 1
if __name__=='__main__':raise SystemExit(main())
