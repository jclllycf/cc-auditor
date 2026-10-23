"""发行边界负例，不包含真实秘密或真实用户资料。"""
import tempfile,unittest,zipfile
from pathlib import Path
from public_build.release_guard import audit_tree,audit_zip,content_findings,safe_name

class ReleaseGuard(unittest.TestCase):
    def test_private_paths_rejected(self):
        for n in ('../a','/a','a\\b','a:b','assets/claude-web-helper/a.js','AGENTS.md','data/evidence.json'):
            with self.assertRaises(ValueError):safe_name(n)
    def test_credential_and_user_path_blocked_without_value_echo(self):
        values=[b'ghp_'+b'A'*30,b'-----BEGIN '+b'PRIVATE KEY-----\n'+b'A'*64,b'C:\\Users\\'+b'private-person\\file']
        for v in values:
            found=content_findings('fixture.txt',v);self.assertTrue(found);self.assertNotIn(v.decode(),str(found))
    def test_extra_file_rejected_against_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'unexpected.txt').write_text('x')
            with self.assertRaises(ValueError):audit_tree(root,{'files':[]})
    def test_zip_duplicate_and_private_content_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            z=Path(d)/'a.zip'
            with zipfile.ZipFile(z,'w') as stream:stream.writestr('a.txt',b'ghp_'+b'B'*30)
            with self.assertRaises(ValueError):audit_zip(z)
    def test_documented_install_path_is_allowed(self):
        self.assertFalse(content_findings('INSTALL.md',b'C:\\Tools\\CC-Auditor'))
    def test_additional_credential_shapes(self):
        for value in (b'AKIA'+b'A'*16,b'Bearer '+b'A'*30,b'eyJ'+b'A'*20+b'.'+b'B'*20+b'.'+b'C'*20,b'vmess://'+b'A'*30):
            self.assertTrue(content_findings('injected.txt',value))
    def test_reviewed_upstream_exception_never_suppresses_secrets(self):
        from public_build.release_guard import reviewed_findings,sha
        raw=b'Bearer '+b'A'*30
        policy={'x':{'sha256':sha(raw),'rules':['private_home','bearer_value']}}
        self.assertTrue(reviewed_findings('x',raw,policy))
if __name__=='__main__':unittest.main()
