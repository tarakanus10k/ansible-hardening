"""Offline tests. No host configuration changes; NOT Debian VM integration tests."""
import pathlib, types, unittest, tempfile, json, os
from unittest.mock import patch
script=pathlib.Path(__file__).with_name('audit-cis-debian13.sh').read_text()
source=script.split("<<'PY'\n",1)[1].rsplit('\nPY',1)[0]
m=types.ModuleType('audit'); exec(compile(source,'embedded-audit','exec'),m.__dict__)
class Tests(unittest.TestCase):
 def test_count(self): self.assertEqual(len(m.checks([])),18)
 def test_rule_order(self):
  self.assertTrue(m.covers('-F perm=aw -k identity -a exit,always -F path=/etc/passwd -F arch=b64','path','/etc/passwd'))
 def test_rule_all(self):
  self.assertTrue(m.covers('-a always,exit -F arch=b64 -S all -F path=/etc/passwd -F perm=rwa -F key=identity','path','/etc/passwd'))
 def test_bad_rules(self):
  for line in ['-w /etc/passwd -p wa -k identity','-a never,exit -F path=/etc/passwd -F perm=wa','-a always,exit -F path=/etc/passwd -F perm=w','-a always,exit -F path=/etc/passwd -F perm=wa -F auid>=1000','-a always,exit -F path=/etc/passwd -F perm=wa -S open','-a always,exit -F path=/etc/passwd -F perm=wa -F arch=b32','-a always,exit -F path=/etc/passwd.bak -F perm=wa']:
   with self.subTest(line=line): self.assertFalse(m.covers(line,'path','/etc/passwd'))
 def pam(self):
  d={k:[f'{k} required pam_unix.so'] for k in m.COMMON}
  d['auth']+=['auth requisite pam_faillock.so preauth','auth [default=die] pam_faillock.so authfail']
  d['account']+=['account required pam_faillock.so']; return d
 def test_pam_enabled(self):
  with patch.object(m,'pam_data',return_value=self.pam()):
   self.assertTrue(m.pam_unix()[0]); self.assertTrue(m.pam_faillock()[0]); self.assertTrue(m.no_nullok()[0])
 def test_pam_missing(self):
  d=self.pam(); d['session']=[]
  with patch.object(m,'pam_data',return_value=d): self.assertFalse(m.pam_unix()[0])
 def test_nullok(self):
  d=self.pam(); d['auth'][0]+=' nullok'
  with patch.object(m,'pam_data',return_value=d): self.assertFalse(m.no_nullok()[0])
 def test_deny_boundary_and_override(self):
  for value,expected in [('0',False),('1',True),('5',True),('6',False)]:
   with patch.object(m,'pam_data',return_value=self.pam()),patch.object(m,'read',return_value='deny = '+value):
    self.assertEqual(m.faillock_option('deny',lambda v:1<=v<=5)[0],expected)
  d=self.pam(); d['auth'][1]+=' deny=9'
  with patch.object(m,'pam_data',return_value=d),patch.object(m,'read',return_value='deny = 3'):
   self.assertFalse(m.faillock_option('deny',lambda v:1<=v<=5)[0])
 def test_duplicate_config(self):
  with patch.object(m,'pam_data',return_value=self.pam()),patch.object(m,'read',return_value='deny=3\ndeny=9'):
   self.assertFalse(m.faillock_option('deny',lambda v:1<=v<=5)[0])
 def test_unlock(self):
  for value,expected in [('0',True),('899',False),('900',True)]:
   with patch.object(m,'pam_data',return_value=self.pam()),patch.object(m,'read',return_value='unlock_time='+value):
    self.assertEqual(m.faillock_option('unlock_time',lambda v:v==0 or v>=900)[0],expected)
 def test_ssh_match_uncertain(self):
  with patch.object(m,'ssh_inventory',return_value=([],[],['Match User test'])),patch.object(m,'run',return_value='permitrootlogin no'):
   with self.assertRaises(m.AuditError): m.ssh_value('permitrootlogin',lambda v:v=='no',[])
 def test_ssh_effective(self):
  with patch.object(m,'ssh_inventory',return_value=([],[],[])),patch.object(m,'run',return_value='permitrootlogin yes'):
   self.assertFalse(m.ssh_value('permitrootlogin',lambda v:v=='no',[])[0])
 def test_live_and_disk(self):
  rule='-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa'
  def run(*a): return rule if a[-1]=='-l' else 'enabled 1'
  with patch.object(m,'run',side_effect=run),patch.object(m.glob,'glob',return_value=['fixture.rules']),patch.object(m,'read',return_value=rule):
   self.assertTrue(m.audit_rules([('path','/etc/passwd')])[0])
  with patch.object(m,'run',side_effect=run),patch.object(m.glob,'glob',return_value=['fixture.rules']),patch.object(m,'read',return_value=''):
   self.assertFalse(m.audit_rules([('path','/etc/passwd')])[0])
 def test_audit_suppression(self):
  with patch.object(m,'run',side_effect=['-a never,task','enabled 1']),patch.object(m.glob,'glob',return_value=['fixture.rules']),patch.object(m,'read',return_value=''):
   with self.assertRaises(m.AuditError): m.audit_rules([('path','/etc/passwd')])
 def test_html_escaping(self):
  r=dict(host='<host>',timestamp='test',results=[dict(id='x',title='<script>',page=1,result=False,status='FAIL',evidence='<img src=x onerror=alert(1)>')])
  h=m.render(r); self.assertIn('&lt;img',h); self.assertNotIn('<img src=x',h); self.assertIn('&lt;host&gt;',h)

 def test_remote_download_after_false(self):
  for audit_rc in [0,1]:
   with self.subTest(audit_rc=audit_rc), tempfile.TemporaryDirectory() as td:
    dest=pathlib.Path(td)/'results'; calls=[]
    def fake_run(cmd,**kw):
     calls.append(cmd)
     if cmd[0]=='ssh':
      if cmd[-1]=='id -u; id -g': return types.SimpleNamespace(returncode=0,stdout='1000\n1000\n')
      if 'mktemp' in cmd[-1]: return types.SimpleNamespace(returncode=0,stdout='/tmp/cis-audit.abcdefghij\n')
      if '-t' in cmd: return types.SimpleNamespace(returncode=audit_rc,stdout='')
      return types.SimpleNamespace(returncode=0,stdout='')
     if cmd[-2].endswith('/report.json'):
      pathlib.Path(cmd[-1]).write_text(json.dumps({'results':[{'result':True}]*18}))
     elif cmd[-2].endswith('/report.html'): pathlib.Path(cmd[-1]).write_text('<html>fixture</html>')
     return types.SimpleNamespace(returncode=0,stdout='')
    a=types.SimpleNamespace(remote='user@example',output_dir=str(dest),port=2222,identity='/key with spaces',ssh_context=[])
    with patch.object(m.subprocess,'run',side_effect=fake_run),patch.dict(os.environ,{'CIS_AUDIT_SCRIPT_PATH':str(pathlib.Path(__file__).with_name('audit-cis-debian13.sh'))}):
     self.assertEqual(m.remote_audit(a),audit_rc)
    self.assertTrue((dest/'report.html').exists()); self.assertTrue((dest/'report.json').exists())
    self.assertTrue(any('rmdir' in c[-1] for c in calls))
 def test_remote_no_overwrite(self):
  with tempfile.TemporaryDirectory() as td:
   a=types.SimpleNamespace(remote='server',output_dir=td,port=None,identity=None)
   with self.assertRaises(m.AuditError): m.remote_audit(a)
 def test_remote_reject_option_injection(self):
  a=types.SimpleNamespace(remote='-oProxyCommand=bad')
  with self.assertRaises(m.AuditError): m.remote_audit(a)


 def test_expanded_syscalls(self):
  required=frozenset(['open','openat','chmod','chown'])
  base='-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -F key=identity -S '
  with patch.object(m,'permission_syscalls',return_value=required):
   self.assertTrue(m.covers(base+'open,chmod,openat,chown','path','/etc/passwd'))
   self.assertFalse(m.covers(base+'open,chmod,openat','path','/etc/passwd'))
 def test_expansion_unavailable(self):
  with patch.object(m,'permission_syscalls',return_value=frozenset()):
   self.assertFalse(m.covers('-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -S open','path','/etc/passwd'))
 def test_late_delete_all_augenrules(self):
  rule='-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa'
  def run(*args): return rule if args[-1]=='-l' else 'enabled 1'
  def read(name): return '-D\n-b 8192\n-f 1' if name.endswith('/audit.rules') else rule
  with patch.object(m,'run',side_effect=run),patch.object(m.glob,'glob',return_value=['/etc/audit/rules.d/50-identity.rules','/etc/audit/rules.d/audit.rules']),patch.object(m,'read',side_effect=read):
   self.assertTrue(m.audit_rules([('path','/etc/passwd')])[0])

if __name__=='__main__': unittest.main()
