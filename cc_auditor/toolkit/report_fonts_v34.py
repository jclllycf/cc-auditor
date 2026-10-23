"""Private, bundled CJK font registration. No OS installation or network."""
import hashlib
import sys
from pathlib import Path

FONT_FAMILY='CC Auditor Sans SC'
FONT_ASSETS={'CCAuditorSansSC-Regular.ttf':'4e6463dd7ad9740733a04f2e0c6f028b10f1e182af0e835a8f25bd393f80a485',
             'CCAuditorSansSC-Bold.ttf':'9a8ae5cdc3edb882de72e040b4fa1bc04bc4bf7b8eddd2e92429bf7edc7d5f66'}
_APP=None
_FONT_ID=None


def ensure_report_font():
    global _APP,_FONT_ID
    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QFont,QFontDatabase,QRawFont
    _APP=QApplication.instance() or QApplication([])
    if _FONT_ID is None:
        root=Path(sys._MEIPASS) if getattr(sys,'frozen',False) else Path(__file__).resolve().parents[2]
        ids=[]
        for name,digest in FONT_ASSETS.items():
            path=root/'assets/report-fonts'/name
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
                raise ValueError('report_font_asset_missing_or_changed')
            font_id=QFontDatabase.addApplicationFont(str(path))
            if font_id<0 or FONT_FAMILY not in QFontDatabase.applicationFontFamilies(font_id):
                raise ValueError('report_font_cannot_be_loaded')
            ids.append(font_id)
        _FONT_ID=ids
    raw=QRawFont.fromFont(QFont(FONT_FAMILY,10))
    if not raw.isValid() or not all(raw.supportsCharacter(ord(c)) for c in '环境风险证据预检准备'):
        raise ValueError('report_font_chinese_glyphs_unavailable')
    return FONT_FAMILY
