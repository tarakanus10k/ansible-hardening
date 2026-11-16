#!/usr/bin/env bash
# CIS Debian 13 v1.1.0: 20 selected controls. Read-only configuration audit.
# Python 3 standard library is embedded for safe parsing and HTML/JSON output.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
command -v python3 >/dev/null || { echo 'Required: python3' >&2; exit 2; }
export CIS_AUDIT_SCRIPT_PATH="${BASH_SOURCE[0]}"
exec python3 - "$@" <<'PY'
import argparse, ctypes, datetime, decimal, hashlib, functools, glob, html, json, os, pathlib, re, shlex, socket, stat, subprocess, sys
P = pathlib.Path
REPO = 'ff2b4a9d16a9b9c3e98e259cb4f5e19c2c834b49'
AUDITOR_VERSION = '4.0'
class AuditError(Exception): pass

def run(*args):
    try:
        p = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=30, env={**os.environ, 'LC_ALL':'C'})
    except (OSError, subprocess.TimeoutExpired) as e: raise AuditError(str(e))
    if p.returncode: raise AuditError(f'{shlex.join(args)}: rc={p.returncode}; {p.stderr.strip() or p.stdout.strip()}')
    return p.stdout.strip()

def read(path):
    try: return P(path).read_text()
    except (OSError, UnicodeError) as e: raise AuditError(str(e))

def lines(text):
    return [x.split('#',1)[0].strip() for x in text.replace('\\\n',' ').splitlines()
            if x.split('#',1)[0].strip()]

def permission(path, allowed, directory=False):
    s = P(path).stat()
    kind = stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)
    mode = stat.S_IMODE(s.st_mode)
    return kind and s.st_uid == 0 and s.st_gid == 0 and not (mode & ~allowed), f'{path}: mode={mode:04o}, uid={s.st_uid}, gid={s.st_gid}'

def ssh_inventory():
    files, dirs, seen, matches = set(), {'/etc/ssh/sshd_config.d'}, set(), []
    def visit(path):
        real = str(P(path).resolve())
        if real in seen: return
        seen.add(real); files.add(path)
        for line in lines(read(path)):
            tokens = shlex.split(line)
            if not tokens: continue
            if tokens[0].lower() == 'match': matches.append(f'{path}: {line}')
            if tokens[0].lower() == 'include':
                for pattern in tokens[1:]:
                    if not os.path.isabs(pattern): pattern = '/etc/ssh/' + pattern
                    parent = os.path.dirname(pattern)
                    for d in glob.glob(parent):
                        if P(d).is_dir(): dirs.add(d)
                    for child in sorted(glob.glob(pattern)):
                        dirs.add(str(P(child).parent)); visit(child)
    visit('/etc/ssh/sshd_config')
    if P('/etc/ssh/sshd_config.d').is_dir():
        for root, ds, fs in os.walk('/etc/ssh/sshd_config.d', onerror=lambda e: (_ for _ in ()).throw(e)):
            for f in fs:
                if f.endswith('.conf'): visit(str(P(root)/f))
    return files, dirs, matches

def ssh_permissions(directory=False):
    files, dirs, _ = ssh_inventory()
    results = [permission(x, 0o700 if directory else 0o600, directory) for x in sorted(dirs if directory else files)]
    return all(x[0] for x in results), '\n'.join(x[1] for x in results)

def ssh_value(key, predicate, contexts):
    _, _, matches = ssh_inventory()
    run('sshd','-t')
    evidence=[]; ok=True
    for context in [None]+contexts:
        cmd=['sshd','-T'] + (['-C',context] if context else [])
        data=dict(x.split(None,1) for x in run(*cmd).splitlines() if len(x.split(None,1))==2)
        value=data.get(key,'')
        ok = bool(predicate(value)) and ok
        evidence.append(f'{context or "global"}: {key}={value or "MISSING"}')
    if matches:
        # A finite set of connections cannot prove every Match branch safe.
        raise AuditError('Match blocks require review of all relevant connection contexts. '
                         'Result is conservative false even with --ssh-context.\n'+'\n'.join(evidence+matches))
    return ok, '\n'.join(evidence)+'\nsshd -T reads disk configuration; it does not prove the running daemon reloaded it.'

COMMON = ['account','auth','password','session','session-noninteractive']
def pam_data(): return {k:lines(read('/etc/pam.d/common-'+k)) for k in COMMON}
def module_rows(data, key, module):
    return [x for x in data[key] if re.search(r'(?:^|\s)(?:\S*/)?'+re.escape(module)+r'(?:\s|$)',x)]
def pam_unix():
    d=pam_data(); rows={k:module_rows(d,k,'pam_unix.so') for k in COMMON}
    return all(rows.values()), '\n'.join(f'{k}: {v}' for k,v in rows.items())
def pam_faillock():
    d=pam_data(); a=module_rows(d,'auth','pam_faillock.so'); c=module_rows(d,'account','pam_faillock.so')
    ok=any('preauth' in x.split() for x in a) and any('authfail' in x.split() for x in a) and bool(c)
    return ok, '\n'.join(a+c) or 'pam_faillock missing in common-auth/common-account'
def faillock_option(key, predicate):
    d=pam_data(); conf=lines(read('/etc/security/faillock.conf'))
    vals=[re.fullmatch(re.escape(key)+r'\s*=\s*(\d+)',x) for x in conf if re.match(re.escape(key)+r'\s*=',x)]
    if len(vals)!=1 or vals[0] is None: return False, f'{key}: require one explicit numeric setting in faillock.conf'
    values=[int(vals[0][1])]; evidence=[f'faillock.conf: {key}={values[0]}']
    for k in ['auth','account']:
        for row in module_rows(d,k,'pam_faillock.so'):
            if re.search(r'\bconf\s*=',row): raise AuditError('Alternate faillock conf= requires manual review: '+row)
            for value in re.findall(r'\b'+key+r'\s*=\s*([^\s]+)', row):
                if not value.isdigit(): raise AuditError('Invalid PAM argument: '+row)
                values.append(int(value)); evidence.append(f'{k}: {key}={value}')
    enabled,_=pam_faillock()
    return enabled and all(predicate(v) for v in values), '\n'.join(evidence)+f'\npam_faillock present: {enabled}'
def no_nullok():
    d=pam_data(); bad=[k+': '+x for k in COMMON for x in module_rows(d,k,'pam_unix.so') if 'nullok' in x.split()]
    enabled,_=pam_unix()
    return enabled and not bad, '\n'.join(bad) or f'nullok absent; pam_unix in all five stacks: {enabled}'
def packages(names):
    out=[]; ok=True
    for name in names:
        value=run('dpkg-query','-W','-f=${Status}',name)
        out.append(f'{name}: {value}'); ok = ok and value=='install ok installed'
    return ok,'\n'.join(out)

def installed_sudo():
    evidence=[]; found=False
    for name in ['sudo','sudo-rs']:
        try:
            p=subprocess.run(['dpkg-query','-W','-f=${Status}',name],text=True,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
                             env={**os.environ,'LC_ALL':'C'})
        except (OSError,subprocess.TimeoutExpired) as e: raise AuditError(str(e))
        if p.returncode not in (0,1): raise AuditError('dpkg-query: '+p.stderr.strip())
        ok=p.returncode==0 and p.stdout.strip()=='install ok installed'
        found=found or ok
        evidence.append(name+': '+(p.stdout.strip() or 'not installed'))
    return found,'\n'.join(evidence)+'\nLocal sudoers policy; libsss-sudo/sssd are optional unless LDAP/SSSD sudo policy is required.'

def evaluate_timeout(policy):
    if not isinstance(policy,dict) or not isinstance(policy.get('Defaults',[]),list):
        raise AuditError('Unexpected cvtsudoers JSON schema')
    values=[]; evidence=[]; global_found=False
    for entry in policy.get('Defaults',[]):
        for option in entry.get('Options',[]):
            if 'timestamp_timeout' not in option: continue
            raw=option['timestamp_timeout']
            if isinstance(raw,bool): raise AuditError('Non-numeric timestamp_timeout')
            try: value=decimal.Decimal(str(raw))
            except decimal.InvalidOperation: raise AuditError('Invalid timestamp_timeout: '+str(raw))
            if not value.is_finite(): raise AuditError('Non-finite timestamp_timeout')
            values.append(value)
            binding=entry.get('Binding')
            if not binding: global_found=True
            evidence.append('timestamp_timeout='+str(raw)+' minutes; binding='+json.dumps(binding or 'global',ensure_ascii=False))
    if not values: return False,'No explicit timestamp_timeout in parsed active sudoers policy (compiled defaults do not satisfy CIS 5.2.6)'
    if not global_found:
        return False,'\n'.join(evidence)+'\nOnly scoped settings found; universal explicit coverage is not demonstrated.'
    ok=all(decimal.Decimal(0)<=v<=decimal.Decimal(15) for v in values)
    return ok,'\n'.join(evidence)+'\nCIS range: 0..15 inclusive; all explicit scoped overrides checked.'

def sudo_timeout():
    installed,detail=installed_sudo()
    if not installed: return False,detail
    # Parse with sudo's own grammar, including nested includes, comments,
    # continuation lines and ignored includedir backup files. No shell grep.
    run('visudo','-c')
    nss=lines(read('/etc/nsswitch.conf'))
    for row in nss:
        if row.startswith('sudoers:') and re.search(r'\b(sss|ldap)\b',row):
            raise AuditError('External sudo policy requires a separate audit: '+row)
    version=run('sudo','-V')
    if 'sudo-rs' in version.lower():
        raise AuditError('sudo-rs found: implementation-specific timeout verification required; classic sudo parser is not authoritative')
    cmd=['cvtsudoers','-c','/dev/null','-i','sudoers','-f','json','-d','all','-s','aliases,privileges','/etc/sudoers']
    try:
        parsed=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
                              env={**os.environ,'LC_ALL':'C'})
    except (OSError,subprocess.TimeoutExpired) as e: raise AuditError(str(e))
    if parsed.returncode or parsed.stderr.strip():
        raise AuditError('cvtsudoers did not parse the policy cleanly: '+parsed.stderr.strip())
    policy=json.loads(parsed.stdout) if parsed.stdout.strip() else {}
    ok,evidence=evaluate_timeout(policy)
    return ok,evidence+'\nvisudo syntax: OK; parsed by cvtsudoers. No sudo authentication attempts performed.'

def pam_latest():
    ok,detail=packages(['libpam-runtime'])
    installed=run('dpkg-query','-W','-f=${Version}','libpam-runtime')
    policy=run('apt-cache','policy','libpam-runtime')
    m=re.search(r'^\s*Candidate:\s*(\S+)',policy,re.M)
    if not m or m[1]=='(none)': raise AuditError('APT candidate unavailable; run apt-get update separately')
    # Do not update APT lists: no network/configuration mutation during audit.
    return ok and installed==m[1], detail+f'\ninstalled={installed}; candidate={m[1]}\nBased on local APT metadata only; refresh it before the audit.'
def audit_service():
    e=run('systemctl','is-enabled','auditd'); a=run('systemctl','is-active','auditd')
    return e=='enabled' and a=='active', f'enabled={e}; active={a}'

def parse_rule(line):
    t=shlex.split(line); fields={}; action=None; syscalls=[]; unsupported=[]; i=0
    while i<len(t):
        token=t[i]
        if token in ['-a','-A','-F','-S','-k'] and i+1<len(t):
            value=t[i+1]; i+=2
            if token in ['-a','-A']: action=set(value.split(','))
            elif token=='-F':
                if '=' not in value: unsupported.append(value)
                else:
                    k,v=value.split('=',1)
                    if k in fields: unsupported.append('duplicate '+k)
                    fields[k]=v
            elif token=='-S': syscalls += value.split(',')
            continue
        unsupported.append(token); i+=1
    return action,fields,syscalls,unsupported


@functools.lru_cache(maxsize=1)
def permission_syscalls():
    """Use installed libaudit to expand arch=b64,perm=wa IN MEMORY only.
    No audit socket is opened; no rules are sent to the kernel.
    Old libraries without expansion return an empty set (fail closed).
    """
    class RulePrefix(ctypes.Structure):
        _fields_=[('flags',ctypes.c_uint32),('action',ctypes.c_uint32),
                  ('field_count',ctypes.c_uint32),('mask',ctypes.c_uint32*64)]
    try:
        lib=ctypes.CDLL('libaudit.so.1')
        lib.audit_rule_create_data.restype=ctypes.c_void_p
        lib.audit_rule_create_data.argtypes=[]
        lib.audit_rule_free_data.argtypes=[ctypes.c_void_p]
        lib.audit_rule_free_data.restype=None
        lib.audit_rule_fieldpair_data.argtypes=[ctypes.POINTER(ctypes.c_void_p),ctypes.c_char_p,ctypes.c_int]
        lib.audit_rule_fieldpair_data.restype=ctypes.c_int
        lib.audit_name_to_machine.argtypes=[ctypes.c_char_p]
        lib.audit_name_to_machine.restype=ctypes.c_int
        lib.audit_syscall_to_name.argtypes=[ctypes.c_int,ctypes.c_int]
        lib.audit_syscall_to_name.restype=ctypes.c_char_p
        machine=lib.audit_name_to_machine(os.uname().machine.encode())
        if machine<0: return frozenset()
        ptr=ctypes.c_void_p(lib.audit_rule_create_data())
        if not ptr.value: return frozenset()
        try:
            for field in [b'arch=b64',b'perm=wa']:
                # AUDIT_FILTER_EXIT = 4; mutable buffer since libaudit parses in place.
                buf=ctypes.create_string_buffer(field)
                if lib.audit_rule_fieldpair_data(ctypes.byref(ptr),buf,4): return frozenset()
            mask=ctypes.cast(ptr,ctypes.POINTER(RulePrefix)).contents.mask
            numbers=[n for n in range(2048) if mask[n//32] & (1 << (n%32))]
            if not numbers or len(numbers)==2048: return frozenset()
            names=[]
            for n in numbers:
                name=lib.audit_syscall_to_name(n,machine)
                if not name: return frozenset()
                names.append(name.decode())
            return frozenset(names)
        finally: lib.audit_rule_free_data(ptr)
    except (OSError,AttributeError,UnicodeError):
        return frozenset()

def covers(line, field, path):
    action,f,sc,unsupported=parse_rule(line)
    allowed={'path','dir','perm','arch','key'}
    arch_ok=f.get('arch') in [None,'b64','c000003e','c00000b7']
    return (action=={'always','exit'} and f.get(field,'').rstrip('/')==path.rstrip('/')
            and {'w','a'} <= set(f.get('perm','')) and arch_ok
            and not (set(f)-allowed) and not unsupported
            and (not sc or set(sc)=={'all'} or
                 (f.get('arch') is not None and bool(permission_syscalls()) and permission_syscalls() <= set(sc))))
def audit_rules(targets):
    live=lines(run('auditctl','-l')); status=run('auditctl','-s')
    if not re.search(r'^enabled\s+[12]\s*$',status,re.M): return False,'Kernel auditing disabled'
    names=sorted(glob.glob('/etc/audit/rules.d/*.rules'),
                 key=lambda x:[(0,int(v)) if v.isdigit() else (1,v) for v in re.split(r'(\d+)',x)])
    if not names: return False,'No persistent *.rules files'
    disk=[]
    for n in names:
        for line in lines(read(n)):
            # augenrules moves a standalone -D to the BEGINNING, even
            # when it occurs in a later file (for example audit.rules).
            if line=='-D': continue
            else: disk.append(line)
    # Suppressions/deletions may invalidate superficially matching allow rules.
    for source,rows in [('loaded',live),('persistent',disk)]:
        for row in rows:
            if re.search(r'\bnever\b',row) or re.match(r'^-(?:d|D|W)(?:\s|$)',row) or re.match(r'^-e\s+0\s*$',row):
                raise AuditError(f'{source}: suppression/deletion needs review: {row}')
    ok=True; evidence=[]
    for field,path in targets:
        for source,rows in [('loaded',live),('persistent',disk)]:
            hits=[x for x in rows if covers(x,field,path)]
            ok=ok and bool(hits)
            candidates=[x for x in rows if path in x]
            evidence.append(f'{source} {path}: '+ (' | '.join(hits) if hits else 'MISSING compliant syscall rule'))
            if not hits:
                evidence.append('Candidate lines: '+ (' | '.join(candidates) if candidates else '(none)'))
                if any(' -S ' in x for x in candidates):
                    evidence.append('Required perm=wa syscalls from local libaudit: '+(','.join(sorted(permission_syscalls())) or '(expansion unavailable)'))
    return ok,'\n'.join(evidence)

def checks(contexts):
    return [
      ('5.1.1','Права файлов конфигурации SSH',558,lambda:ssh_permissions()),
      ('5.1.2','Права каталогов конфигурации SSH',561,lambda:ssh_permissions(True)),
      ('5.1.15','LoginGraceTime: 1–60 секунд',595,lambda:ssh_value('logingracetime',lambda v:v.isdigit() and 1<=int(v)<=60,contexts)),
      ('5.1.18','MaxAuthTries: не более 4',602,lambda:ssh_value('maxauthtries',lambda v:v.isdigit() and 0<=int(v)<=4,contexts)),
      ('5.1.21','PermitEmptyPasswords: no',608,lambda:ssh_value('permitemptypasswords',lambda v:v=='no',contexts)),
      ('5.1.22','PermitRootLogin: no',610,lambda:ssh_value('permitrootlogin',lambda v:v=='no',contexts)),
      ('5.2.1','Установлен sudo или sudo-rs',618,installed_sudo),
      ('5.2.6','sudo timestamp_timeout: явно задан, 0–15 минут',631,sudo_timeout),
      ('5.3.1.1','Актуальность libpam-runtime',636,pam_latest),
      ('5.3.2.1','pam_unix включён',645,pam_unix),
      ('5.3.2.2','pam_faillock включён',647,pam_faillock),
      ('5.3.3.1.1','faillock deny: 1–5',658,lambda:faillock_option('deny',lambda v:1<=v<=5)),
      ('5.3.3.1.2','faillock unlock_time: 0 или ≥900',660,lambda:faillock_option('unlock_time',lambda v:v==0 or v>=900)),
      ('5.3.3.4.1','pam_unix без nullok',702,no_nullok),
      ('6.2.1.1','Установлены auditd и audispd-plugins',816,lambda:packages(['auditd','audispd-plugins'])),
      ('6.2.1.2','auditd включён и активен',818,audit_service),
      ('6.2.3.1','Аудит sudoers и sudoers.d',838,lambda:audit_rules([('path','/etc/sudoers'),('dir','/etc/sudoers.d')])),
      ('6.2.3.12','Аудит /etc/group',871,lambda:audit_rules([('path','/etc/group')])),
      ('6.2.3.13','Аудит /etc/passwd',874,lambda:audit_rules([('path','/etc/passwd')])),
      ('6.2.3.14','Аудит shadow и gshadow',877,lambda:audit_rules([('path','/etc/shadow'),('path','/etc/gshadow')]))]

def render(report):
    esc=html.escape; rows=report['results']; passed=sum(r['result'] for r in rows)
    cards=''.join(f'<div class="card"><b>{v}</b><span>{k}</span></div>' for k,v in [('Проверок',len(rows)),('true',passed),('false',len(rows)-passed)])
    body=''
    for r in rows:
        val=str(r['result']).lower()
        body+=f'<tr data-result="{val}"><td><strong>{esc(r["id"])}</strong><small>PDF · стр. {r["page"]}</small></td><td>{esc(r["title"])}</td><td><span class="badge {val}">{val}</span><small>{esc(r["status"])}</small></td><td><details><summary>Доказательства</summary><pre>{esc(r["evidence"])}</pre></details></td></tr>'
    return '''<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CIS Debian 13 · аудит</title><style>
    *{box-sizing:border-box}body{margin:0;background:#f1f5f9;color:#172a40;font:15px/1.6 system-ui,sans-serif}main{max-width:1250px;margin:auto;padding:36px 24px}header{background:#10283e;color:white;padding:32px;border-radius:18px}h1{font-size:30px;margin:8px 0}header p{color:#cbd5e1;margin:4px 0}.eyebrow{letter-spacing:2px;font-size:12px;color:#7dd3fc}.cards{display:flex;gap:16px;margin:22px 0}.card{background:white;border:1px solid #dae3ec;border-radius:14px;padding:18px 26px;flex:1}.card b{display:block;font-size:32px}.card span,small{color:#64748b}small{display:block;font-size:12px}.notice{border-left:4px solid #0284c7;background:#e0f2fe;padding:15px 20px;margin:20px 0}button{background:white;border:1px solid #bdcbd9;border-radius:8px;padding:9px 16px;margin:0 8px 16px 0;cursor:pointer}button:hover{background:#dbeafe}.table{overflow:auto;border-radius:12px;background:white}table{border-collapse:collapse;width:100%;min-width:750px}th{text-align:left;background:#e2e8f0;padding:14px}td{padding:15px;border-top:1px solid #e2e8f0;vertical-align:top}td:nth-child(1){width:135px}td:nth-child(2){width:32%}.badge{padding:4px 12px;border-radius:20px;font-weight:700}.true{color:#166534;background:#dcfce7}.false{color:#991b1b;background:#fee2e2}summary{cursor:pointer;color:#0369a1}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;max-width:550px}footer{margin-top:22px;color:#64748b;font-size:12px}@media print{button{display:none}main{padding:0}details pre{display:block}.table{overflow:visible}header{color:black;background:white}}
    </style><main><header><div class="eyebrow">CONFIGURATION AUDIT · SELECTED CONTROLS</div><h1>CIS Debian Linux 13 · v1.1.0</h1><p>'''+esc(report['host'])+' · '+esc(report['timestamp'])+'''</p><p>SSH / PAM / sudo / auditd · 20 правил проекта</p></header><div class="cards">'''+cards+'''</div><div class="notice">true — проверка пройдена. false — несоответствие либо проверка не подтверждена (ERROR / REVIEW). Это выборочный аудит, не сертификация CIS и не функциональный тест атак. Параметры SSH проверяются на диске, auditd — также в ядре. Актуальность PAM определяется по локальному кэшу APT.</div><button onclick="filterRows('all')">Все</button><button onclick="filterRows('false')">Только false</button><button onclick="filterRows('true')">Только true</button><div class="table"><table><thead><tr><th>CIS</th><th>Проверка</th><th>Результат</th><th>Обоснование</th></tr></thead><tbody>'''+body+'''</tbody></table></div><footer>Основание: предоставленный CIS Debian Linux 13 Benchmark v1.1.0, 26.08.2026. Номера страниц печатные.<br>Эталон покрытия (не версия, обнаруженная на сервере): '''+REPO+'''<br>Независимый учебный скрипт; не официальный продукт CIS.</footer></main><script>function filterRows(v){document.querySelectorAll('tbody tr').forEach(r=>r.hidden=v!=='all'&&r.dataset.result!==v)}</script></html>'''


def remote_audit(args):
    """Run on one SSH host, fetch reports even when audit returns 1."""
    target=args.remote
    if target.startswith('-') or not re.fullmatch(r'[A-Za-z0-9_.@:\[\]-]+',target):
        raise AuditError('Use an SSH config alias or user@host without spaces/options')
    dest=P(args.output_dir).absolute()
    if not dest.parent.is_dir() or dest.exists() or dest.is_symlink():
        raise AuditError('Local output directory must be new; parent must exist')
    ssh=['ssh']; scp=['scp']
    if args.port:
        ssh+=['-p',str(args.port)]; scp+=['-P',str(args.port)]
    if args.identity:
        ssh+=['-i',args.identity]; scp+=['-i',args.identity]
    script=P(os.environ.get('CIS_AUDIT_SCRIPT_PATH',''))
    if not script.is_file(): raise AuditError('Cannot locate the Bash script for upload')
    def remote_exec(command, **kwargs):
        # Python source arrives over stdin from a heredoc. Reattach SSH stdin
        # to the controlling terminal so sudo can actually prompt for a password.
        try: tty = open('/dev/tty', 'rb')
        except OSError: tty = None
        try:
            return subprocess.run(command, stdin=tty if tty else subprocess.DEVNULL, **kwargs)
        finally:
            if tty: tty.close()
    # Interactive SSH/sudo prompts remain on the user's terminal.
    def ssh_text(command):
        p=remote_exec(ssh+[target,command],text=True,stdout=subprocess.PIPE)
        if p.returncode: raise AuditError(f'SSH command failed: rc={p.returncode}')
        return p.stdout.strip()
    ids=ssh_text('id -u; id -g').splitlines()
    if len(ids)!=2 or not all(x.isdigit() for x in ids):
        raise AuditError('Unexpected remote uid/gid output')
    uid,gid=ids
    work=ssh_text('umask 077; mktemp -d /tmp/cis-audit.XXXXXXXXXX')
    if not re.fullmatch(r'/tmp/cis-audit\.[A-Za-z0-9]{10}',work):
        raise AuditError('Unexpected remote temporary directory; no files removed')
    print('Remote workspace: '+work,file=sys.stderr)
    uploaded=work+'/audit.sh'; reports=work+'/reports'
    try:
        p=remote_exec(scp+[str(script),target+':'+uploaded])
        if p.returncode: raise AuditError('Script upload failed')
        inner=['bash',uploaded,'--output-dir',reports]
        for context in args.ssh_context: inner+=['--ssh-context',context]
        # Ownership change happens in the SAME sudo session; no second password
        # prompt or NOPASSWD rule is needed to download the reports.
        body=shlex.join(inner)+ '; rc=$?; '
        body+='if [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ]; then '
        body+='chown -- '+uid+':'+gid+' '+shlex.join([reports,reports+'/report.html',reports+'/report.json'])+' || exit 2; fi; exit "$rc"'
        command=shlex.join(([] if uid=='0' else ['sudo','--'])+['bash','-c',body])
        p=remote_exec(ssh+['-t',target,command])
        if p.returncode not in (0,1):
            raise AuditError(f'Remote audit failed: rc={p.returncode}; reports not assumed complete')
        audit_rc=p.returncode
        os.umask(0o077); dest.mkdir(mode=0o700)
        for name in ['report.html','report.json']:
            p=remote_exec(scp+[target+':'+reports+'/'+name,str(dest/name)])
            if p.returncode: raise AuditError(f'Download failed: {name}; partial local directory retained')
            (dest/name).chmod(0o600)
        data=json.loads((dest/'report.json').read_text())
        expected_ids={item[0] for item in checks([])}
        if (len(data.get('results',[]))!=len(expected_ids) or
            {r.get('id') for r in data['results']}!=expected_ids or
            any(type(r.get('result')) is not bool for r in data['results'])):
            raise AuditError('Downloaded JSON does not match the expected control set')
        print(f'Downloaded: {dest}/report.html and report.json',file=sys.stderr)
        # Delete only the known files created by this run, after both downloads.
        cleanup='rm -f -- '+shlex.join([uploaded,reports+'/report.html',reports+'/report.json'])
        cleanup+=' && rmdir -- '+shlex.join([reports,work])
        try: ssh_text(cleanup)
        except AuditError as e: print('Reports saved, but remote cleanup failed: '+str(e),file=sys.stderr)
        return audit_rc
    except (AuditError,OSError,ValueError):
        print('Remote files retained for recovery: '+work,file=sys.stderr)
        raise

def main():
    ap=argparse.ArgumentParser(description='Read-only audit of 20 project controls, CIS Debian 13 v1.1.0. Requires root and Python 3.')
    ap.add_argument('--remote',help='SSH config alias or user@host; downloads reports to the local output directory')
    ap.add_argument('--port',type=int,help='SSH port')
    ap.add_argument('--identity',help='Path to SSH private key on the local machine')
    ap.add_argument('--output-dir',default='cis-audit-report',help='New report directory (must not exist)')
    ap.add_argument('--ssh-context',action='append',default=[],help='Extra sshd -C context; repeatable. Match still requires manual review.')
    args=ap.parse_args()
    if args.port is not None and not 1<=args.port<=65535: ap.error('Invalid SSH port')
    if args.remote: return remote_audit(args)
    if args.port or args.identity: ap.error('--port and --identity require --remote')
    if os.geteuid()!=0: ap.error('Run with sudo/root')
    osrelease=read('/etc/os-release')
    if not re.search(r'^ID=["\']?debian["\']?$',osrelease,re.M) or not re.search(r'^VERSION_ID=["\']?13["\']?$',osrelease,re.M):
        ap.error('This audit targets Debian 13 only')
    os.umask(0o077)
    dest=P(args.output_dir).absolute()
    # Never overwrite a previous report or follow an existing report-directory symlink.
    dest.mkdir(mode=0o700,parents=False,exist_ok=False)
    results=[]
    for ident,title,page,fn in checks(args.ssh_context):
        try:
            ok, evidence=fn(); status='PASS' if ok else 'FAIL'
        except (AuditError,OSError,ValueError) as e:
            ok=False; evidence=str(e); status='ERROR / REVIEW'
        results.append(dict(id=ident,title=title,page=page,result=bool(ok),status=status,evidence=evidence))
        print(f'{ident}\t{str(bool(ok)).lower()}\t{status}',flush=True)
    script_path=P(os.environ.get('CIS_AUDIT_SCRIPT_PATH',''))
    script_sha256=hashlib.sha256(script_path.read_bytes()).hexdigest() if script_path.is_file() else None
    report=dict(benchmark='CIS Debian Linux 13 v1.1.0',reference_repository_commit=REPO,
                auditor_version=AUDITOR_VERSION,auditor_sha256=script_sha256,host=socket.gethostname(),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),results=results)
    (dest/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    (dest/'report.html').write_text(render(report))
    print(f'Reports: {dest}/report.html and report.json',file=sys.stderr)
    return 0 if all(x['result'] for x in results) else 1
if __name__=='__main__':
    try: sys.exit(main())
    except (OSError,AuditError) as e: print(f'ERROR: {e}',file=sys.stderr); sys.exit(2)
PY
