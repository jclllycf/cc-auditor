"""Strict, offline acceptance of v3.4 Chinese PDF output.

Checks actual embedded page resources and selectable Chinese text, rather
than trusting that QPdfWriter successfully created a nonempty file.
"""
from __future__ import annotations

import re
from pathlib import Path

from .pdf_report_renderer import pdf_backend


REQUIRED_TEXT = {
    '简明报告': ('首次使用前环境预检', '适合开始准备', '三类行动判断'),
    '完整技术报告': ('首次使用前完整技术报告', '确定指数与行动门槛', '四端'),
    '证据补足清单': ('证据补足清单', '为什么还缺', '最少操作'),
}


def validate_pdf(path, kind, run_id=None, evidence_sha=None, assessment_sha=None):
    """Raise on missing Chinese, unreadable fonts, bad provenance or pages."""
    PdfReader, _ = pdf_backend()
    path = Path(path)
    if not path.is_file() or path.stat().st_size < 1000:
        raise ValueError(f'v34_pdf_missing_or_empty:{kind}')
    reader = PdfReader(str(path), strict=True)
    if not reader.pages:
        raise ValueError(f'v34_pdf_no_pages:{kind}')
    text_parts = []
    for page_idx, page in enumerate(reader.pages):
        fonts = (page.get('/Resources') or {}).get('/Font')
        if not fonts or not fonts.get_object():
            raise ValueError(f'v34_pdf_missing_font:{kind}:page_{page_idx + 1}')
        extracted = page.extract_text() or ''
        if not extracted.strip():
            raise ValueError(f'v34_pdf_unextractable:{kind}:page_{page_idx + 1}')
        text_parts.append(extracted)
    combined = re.sub(r'\s+', '', ''.join(text_parts))
    if len(re.findall(r'[\u4e00-\u9fff]', combined)) < 24:
        raise ValueError(f'v34_pdf_chinese_unreadable:{kind}')
    if '\ufffd' in combined or '\u25a1' in combined:
        raise ValueError(f'v34_pdf_replacement_characters:{kind}')
    for phrase in REQUIRED_TEXT[kind]:
        if phrase not in combined:
            raise ValueError(f'v34_pdf_missing_section:{kind}:{phrase}')
    if run_id is not None and run_id not in combined:
        raise ValueError(f'v34_pdf_run_id_text_corrupted:{kind}')
    if evidence_sha is not None and (evidence_sha[:12] if kind=='简明报告' else evidence_sha) not in combined:
        raise ValueError(f'v34_pdf_evidence_digest_text_corrupted:{kind}')
    meta = reader.metadata or {}
    for key, expected in (('/CCAuditorRunId', run_id),
                          ('/CCAuditorEvidenceSHA256', evidence_sha),
                          ('/CCAuditorAssessmentSHA256', assessment_sha)):
        if expected is not None and meta.get(key) != expected:
            raise ValueError(f'v34_pdf_provenance_mismatch:{kind}:{key}')
    return {'file':path.name,'pages':len(reader.pages),'bytes':path.stat().st_size,
            'chinese_characters':len(re.findall(r'[\u4e00-\u9fff]', combined)),
            'font_resources_verified':True,'text_extractable':True}
