/* ============================================================
   GEOLOCATION + SECURITY AUDIT
   Loaded by server.js and bound to its helpers via install().
   Read-only: finds misconfigurations, reports them with fixes.
   No credential testing, no exploitation, nothing off-subnet.
   ============================================================ */
'use strict';
let CTX = {};
const run = (...a) => CTX.run(...a);
const cached = (...a) => CTX.cached(...a);
const netInfo = (...a) => CTX.netInfo(...a);
const scanWifi = (...a) => CTX.scanWifi(...a);
const wifiInterface = (...a) => CTX.wifiInterface(...a);
const portScan = (...a) => CTX.portScan(...a);
const tcpPing = (...a) => CTX.tcpPing(...a);
const connections = (...a) => CTX.connections(...a);

const GEO_PROVIDERS = [
  { url: 'https://ipinfo.io/json', map: (j) => ({ ip: j.ip, city: j.city, region: j.region, country: j.country, lat: +j.loc.split(',')[0], lon: +j.loc.split(',')[1], isp: j.org, as: null, timezone: j.timezone }) },
  { url: 'https://ipapi.co/json/', map: (j) => ({ ip: j.ip, city: j.city, region: j.region, country: j.country_name, lat: j.latitude, lon: j.longitude, isp: j.org, as: j.asn, timezone: j.timezone }) },
  { url: 'http://ip-api.com/json/?fields=status,message,query,country,regionName,city,lat,lon,isp,as,timezone', map: (j) => ({ ip: j.query, city: j.city, region: j.regionName, country: j.country, lat: j.lat, lon: j.lon, isp: j.isp, as: j.as, timezone: j.timezone }) },
];

async function geoFetch(url, timeoutMs) {
  const { ok, stdout } = await run('curl.exe', [
    '-s', '--max-time', String(Math.round(timeoutMs / 1000)),
    '-H', 'User-Agent: netrecon/2.1', url,
  ], { timeout: timeoutMs + 5000 });
  if (!ok || !stdout.trim()) return null;
  try { return JSON.parse(stdout); } catch { return null; }
}

/* some providers return an ISO code instead of a name */
const COUNTRY_NAMES = {
  KE: 'Kenya', NG: 'Nigeria', ZA: 'South Africa', EG: 'Egypt', GH: 'Ghana', TZ: 'Tanzania',
  UG: 'Uganda', RW: 'Rwanda', ET: 'Ethiopia', US: 'United States', GB: 'United Kingdom',
  CA: 'Canada', IN: 'India', PK: 'Pakistan', BD: 'Bangladesh', AE: 'United Arab Emirates',
  SA: 'Saudi Arabia', QA: 'Qatar', KW: 'Kuwait', OM: 'Oman', DE: 'Germany', FR: 'France',
  NL: 'Netherlands', ES: 'Spain', IT: 'Italy', PL: 'Poland', SE: 'Sweden', NO: 'Norway',
  CN: 'China', JP: 'Japan', KR: 'South Korea', SG: 'Singapore', MY: 'Malaysia', ID: 'Indonesia',
  PH: 'Philippines', VN: 'Vietnam', TH: 'Thailand', AU: 'Australia', NZ: 'New Zealand',
  BR: 'Brazil', MX: 'Mexico', AR: 'Argentina', CO: 'Colombia', KE2: 'Kenya',
};
const countryName = (c) => {
  if (!c) return '';
  return /^[A-Za-z]{2}$/.test(c) ? (COUNTRY_NAMES[c.toUpperCase()] || c.toUpperCase()) : c;
};

let geoLastGood = null;
async function locate() {
  const t0 = Date.now();
  const attempts = [];
  // try the provider that worked last time first, but race them all: a slow or
  // filtered host must not stall the lookup behind a sequential timeout
  const order = geoLastGood
    ? [geoLastGood, ...GEO_PROVIDERS.filter((p) => p !== geoLastGood)]
    : GEO_PROVIDERS;
  const note = (p, why) => { attempts.push(p.url + ' (' + why + ')'); };

  const lookup = (p) => geoFetch(p.url, 6000).then((j) => {
    if (!j) { note(p, 'no response'); throw new Error('empty'); }
    if (j.status === 'fail' || j.error) { note(p, j.message || j.error); throw new Error('refused'); }
    let g;
    try { g = p.map(j); } catch { note(p, 'bad shape'); throw new Error('shape'); }
    if (!isFinite(g.lat) || !isFinite(g.lon)) { note(p, 'no coords'); throw new Error('coords'); }
    return { p, g };
  });

  // race them; drop each loser as it settles so one dead host cannot stall the rest
  let pending = order.map((p) => lookup(p).then((v) => ({ v }), () => ({})));
  let hit = null;
  while (pending.length && !hit) {
    const r = await Promise.race(pending);
    pending = pending.filter((x) => x !== r);
    if (r.v) hit = r.v;
  }
  if (!hit) return { ok: false, error: 'no geolocation provider responded', attempts, elapsed: Date.now() - t0 };
  const { p, g } = hit;
  geoLastGood = p;

  const info = await cached('net', 5000, netInfo).catch(() => null);
  let tzOffsetMin = null, tzName = g.timezone || null;
  try {
    const tzn = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (tzn) tzName = tzn;
  } catch { /* ignore */ }
  try {
    tzOffsetMin = -new Date().getTimezoneOffset() / 60;
  } catch { /* ignore */ }

  return {
    ok: true,
    source: p.url,
    method: 'ip-geolocation',
    accuracyM: 5000,
    ip: g.ip, city: g.city, region: g.region, country: countryName(g.country),
    lat: g.lat, lon: g.lon, isp: g.isp, as: g.as,
    timezone: tzName, tzOffsetMin,
    localIp: info ? info.ipv4 : '',
    gateway: info ? info.gateway : '',
    ispMatchesLink: !!(info && info.ipv4 && g.ip && g.ip !== info.ipv4),
    note: 'IP-derived position, typically accurate to the city/ISP PoP — not a GPS fix.',
    elapsed: Date.now() - t0,
    attempts,
  };
}

/* ============================================================
   SECURITY AUDIT
   Read-only configuration audit of this host, its Wi-Fi link,
   the default gateway and the local /24. Finds misconfigurations
   and reports them with remediation. Performs no exploitation,
   no credential testing and sends nothing off-subnet.
   ============================================================ */
const SEV_W = { critical: 25, high: 12, medium: 5, low: 2, ok: 0, info: 0, unknown: 0 };
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'unknown', 'info', 'ok'];

function finding(id, sev, title, value, detail, fix) {
  return { id, sev, title, value: value == null ? '\u2014' : String(value), detail: detail || '', fix: fix || '' };
}
async function regValue(key, name) {
  const r = await run('reg.exe', ['query', key, '/v', name], { timeout: 8000 });
  if (!r.ok) return null;
  const m = new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s+(\\S+)\\s+(\\S+)\\s*(.*)').exec(r.stdout);
  if (!m) return null;
  return { type: m[1], raw: m[2], data: m[3] };
}
const regNum = (v) => (v ? parseInt(v.raw, 16) : null);
async function svcState(name) {
  const r = await run('sc.exe', ['query', name], { timeout: 8000 });
  const m = /STATE\s+:\s+(\d+)\s+(\S+)/.exec(r.stdout);
  return m ? { code: Number(m[1]), name: m[2], running: m[2] === 'RUNNING' } : null;
}
function filetimeToDate(hex) {
  if (!hex || hex.length < 16) return null;
  // REG_BINARY stores the FILETIME as a little-endian 8-byte value
  const bytes = hex.match(/../g);
  const be = bytes.slice(0, 8).reverse().join('');
  const v = parseInt(be, 16);
  if (!Number.isFinite(v) || v <= 0) return null;
  const ms = v / 10000 - 11644473600000;
  const d = new Date(ms);
  return isNaN(d.getTime()) ? null : d;
}

/* ---- HOST: Windows configuration posture ---- */
async function auditHost() {
  const [fwAll, fwCur, rdp, smb1, uac, accounts, guest, shares, sb, defSvc, nisSvc, autoLogon, remAssist, rmrSvc, usb, build, ubr, avsig, conns, lp] =
    await Promise.all([
      run('netsh.exe', ['advfirewall', 'show', 'allprofiles'], { timeout: 20000 }),
      run('netsh.exe', ['advfirewall', 'show', 'currentprofile'], { timeout: 20000 }),
      regValue('HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server', 'fDenyTSConnections'),
      regValue('HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters', 'SMB1Protocol'),
      regValue('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'EnableLUA'),
      run('net', ['accounts'], { timeout: 12000 }),
      run('net', ['user', 'Guest'], { timeout: 12000 }),
      run('net', ['share'], { timeout: 12000 }),
      regValue('HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State', 'UEFISecureBootEnabled'),
      svcState('WinDefend'),
      svcState('WdNisSvc'),
      regValue('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', 'AutoAdminLogon'),
      regValue('HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance', 'AllowToGetHelp'),
      svcState('RemoteRegistry'),
      regValue('HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR', 'Start'),
      regValue('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'CurrentBuild'),
      regValue('HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', 'UBR'),
      regValue('HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates', 'AVSignatureApplied'),
      connections().catch(() => null),
      regValue('HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem', 'LongPathsEnabled'),
    ]);

  const f = [];
  const txt = (r) => (r && r.stdout) || '';

  // 1. firewall
  const profiles = [];
  const fwRe = /(Domain|Private|Public) Profile Settings:[\s\S]*?State\s+(\w+)/g;
  let m;
  while ((m = fwRe.exec(txt(fwAll)))) profiles.push({ name: m[1], state: m[2] });
  const off = profiles.filter((p) => /off/i.test(p.state));
  const SHORT = { Domain: 'Domain', Private: 'Private', Public: 'Public' };
  f.push(off.length
    ? finding('fw', 'critical', 'Windows Firewall disabled', off.map((p) => p.name).join(', ') + ' off', 'With the firewall off, every listening service is reachable from the network with no filtering.', 'Set each profile back on: netsh advfirewall set allprofiles state on')
    : finding('fw', 'ok', 'Windows Firewall', (profiles.length ? profiles.map((p) => SHORT[p.name] + '=ON').join('  ') : 'all profiles on'), 'All firewall profiles are enforcing BlockInbound / AllowOutbound.'));

  // 2. active network profile
  const cur = /(Domain|Private|Public) Profile Settings:/.exec(txt(fwCur));
  const curName = cur ? cur[1] : 'unknown';
  f.push(curName === 'Private'
    ? finding('profile', 'ok', 'Network profile', 'Private', 'Trusted profile: LAN discovery and file sharing are permitted.', 'No action needed.')
    : curName === 'Public'
      ? finding('profile', 'low', 'Network profile is Public on a local network', 'Public', 'Public profile blocks LAN discovery and treats every peer as hostile. Convenient, but it also hides your own devices from the phone/printer you expect to see.', 'Switch trusted Wi-Fi to Private: Settings > Network & Internet > Wi-Fi > Properties > Network profile type = Private')
      : finding('profile', 'unknown', 'Network profile', curName, 'Could not determine the active network profile.'));

  // 3. RDP
  const rdpOn = rdp ? regNum(rdp) === 0 : null;
  f.push(rdpOn === true
    ? finding('rdp', 'high', 'Remote Desktop enabled', 'fDenyTSConnections = 0', 'RDP is a direct interactive login surface. If it is reachable from beyond this LAN it becomes the first thing an attacker tries.', 'Disable: System Properties > Remote > uncheck "Allow remote assistance"; or set fDenyTSConnections = 1')
    : rdp
      ? finding('rdp', 'ok', 'Remote Desktop', 'disabled', 'No inbound RDP listener is advertised.')
      : finding('rdp', 'unknown', 'Remote Desktop', 'could not read', 'The fDenyTSConnections value was not readable.'));

  // 4. SMBv1
  f.push(smb1 && regNum(smb1) === 1
    ? finding('smb1', 'critical', 'SMBv1 (SMB 445) enabled', 'SMB1Protocol = 1', 'SMBv1 is the mechanism behind WannaCry and is still a common ransomware entry point. Unsupported and unpatched.', 'Disable via PowerShell: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force')
    : finding('smb1', 'ok', 'SMBv1', 'not present / not enabled', 'Legacy SMBv1 is not advertised.'));

  // 5. UAC
  const uacOn = uac ? regNum(uac) === 1 : null;
  f.push(uacOn === false
    ? finding('uac', 'critical', 'User Account Control disabled', 'EnableLUA = 0', 'With UAC off, every process runs with full administrator rights, so any downloaded code escalates silently.', 'Re-enable: set EnableLUA = 1 under HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System and reboot')
    : finding('uac', 'ok', 'User Account Control', 'enabled', 'Admin operations still require consent.'));

  // 6. password policy
  const acc = txt(accounts);
  const minLen = Number(/Minimum password length:\s*(\d+)/.exec(acc)?.[1] ?? NaN);
  const lockout = /Lockout threshold:\s*(.+)/.exec(acc)?.[1]?.trim() || 'unknown';
  const history = /Length of password history maintained:\s*(.+)/.exec(acc)?.[1]?.trim() || 'unknown';
  const maxAge = /Maximum password age \(days\):\s*(\d+)/.exec(acc)?.[1];
  if (isFinite(minLen) && minLen < 8) {
    f.push(finding('pwlen', 'high', 'No minimum password length', minLen + ' characters', 'The local account policy accepts empty and one-character passwords. Any account that authenticates with a password can be guessed without limit.', 'Set a real floor: net accounts /minpw:12  (and enable a lockout below)'));
  } else if (isFinite(minLen)) {
    f.push(finding('pwlen', 'ok', 'Minimum password length', minLen + ' characters', 'Reasonable floor for local accounts.'));
  } else {
    f.push(finding('pwlen', 'unknown', 'Password policy', 'unreadable', 'Could not read the account policy.'));
  }
  if (/^never$/i.test(lockout)) {
    f.push(finding('lockout', 'high', 'No account lockout', lockout, 'Failed sign-ins are never throttled or locked, so password guessing is unlimited. Combined with a short minimum length this is the single most crackable configuration on the machine.', 'Set a threshold: net accounts /lockoutthreshold:10 /lockoutduration:15'));
  } else {
    f.push(finding('lockout', 'ok', 'Account lockout', lockout, 'Repeated failures are throttled.'));
  }
  f.push(history && /none/i.test(history)
    ? finding('pwhist', 'medium', 'No password history', history, 'Users can cycle between the same two passwords indefinitely, so reuse defeats any complexity requirement.', 'net accounts /passwordhistory:24')
    : finding('pwhist', 'ok', 'Password history', history, 'Reuse is bounded.'));
  f.push(maxAge
    ? finding('pwage', 'info', 'Password expiry', maxAge + ' days', 'Expiry is on. It forces rotation but is generally considered weaker than length and complexity, because it pushes users toward predictable patterns.', 'Consider: net accounts /maxpwage:0 (never expire) alongside a long passphrase')
    : finding('pwage', 'info', 'Password expiry', 'never', 'Passwords do not expire.'));

  // 7. guest
  const gActive = /Account active\s+(\w+)/i.exec(txt(guest))?.[1] || 'unknown';
  f.push(/^yes$/i.test(gActive)
    ? finding('guest', 'high', 'Guest account active', gActive, 'Guest is enabled, giving unauthenticated local logon rights.', 'net user Guest /active:no')
    : finding('guest', 'ok', 'Guest account', gActive, 'Guest logon is disabled.'));

  // 8. shares
  const DEFAULT_SHARES = new Set(['c$', 'ipc$', 'admin$', 'print$']);
  const shareRows = txt(shares).split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !/^Share name\b/.test(l) && !/^-{3,}/.test(l) && !/^The command completed/i.test(l));
  const named = shareRows.map((l) => ({ name: l.split(/\s+/)[0], isDefault: DEFAULT_SHARES.has(l.split(/\s+/)[0].toLowerCase()) }));
  const extraShares = named.filter((s) => !s.isDefault);
  f.push(extraShares.length
    ? finding('shares', 'medium', 'Extra network shares exposed', extraShares.map((s) => s.name).join(', '), 'Non-default shares publish data to every authenticated or anonymous peer on the network.', 'Remove with: net share <name> /delete')
    : finding('shares', 'ok', 'Network shares', named.length ? named.map((s) => s.name).join(' ') : 'none', 'Only the built-in administrative shares exist; none are browsable without a credential.'));

  // 9. secure boot
  f.push(sb && regNum(sb) === 1
    ? finding('secureboot', 'ok', 'Secure Boot', 'enabled', 'Firmware verifies the boot chain, blocking unsigned bootkits.')
    : finding('secureboot', 'medium', 'Secure Boot disabled', sb ? sb.raw : 'not detected', 'Without firmware signature verification the boot chain can be replaced below the OS layer.', 'Re-enable in firmware setup, or verify the platform is in Legacy/BIOS mode.'));

  // 10. defender
  f.push(defSvc && defSvc.running
    ? finding('defender', 'ok', 'Microsoft Defender', 'running', 'Real-time protection service is active.')
    : finding('defender', 'critical', 'Microsoft Defender not running', defSvc ? defSvc.name : 'not found', 'Without an endpoint engine, malware runs unimpeded.', 'Start the service: sc start WinDefend'));
  f.push(nisSvc && nisSvc.running
    ? finding('nis', 'ok', 'Defender network inspection', 'running', 'Network inspection component is active.')
    : finding('nis', 'medium', 'Defender network inspection off', nisSvc ? nisSvc.name : 'not found', 'Scanning of network-borne payloads is reduced.'));

  // 11. AV signature freshness
  const avDate = filetimeToDate(avsig && avsig.raw);
  if (avDate) {
    const ageDays = Math.floor((Date.now() - avDate.getTime()) / 86400000);
    f.push(ageDays > 30
      ? finding('avsig', 'high', 'Antivirus signatures stale', ageDays + ' days old', 'Signatures this far out of date will not detect anything published recently.', 'Update: Start > Windows Security > Virus & threat protection > Check for updates')
      : ageDays > 7
        ? finding('avsig', 'medium', 'Antivirus signatures aging', ageDays + ' days old', 'Signatures should refresh automatically within a day or two.', 'Windows Security > Check for updates')
        : finding('avsig', 'ok', 'Antivirus signatures', ageDays + ' day(s) old', 'Signatures are current.'));
  } else {
    f.push(finding('avsig', 'unknown', 'Antivirus signatures', 'unreadable', 'Could not decode the signature timestamp.'));
  }

  // 12. auto admin logon
  const aal = autoLogon ? regNum(autoLogon) : null;
  f.push(aal === 1
    ? finding('autologon', 'high', 'Automatic administrator logon', 'AutoAdminLogon = 1', 'A stored password is used to log in unattended, and it is recoverable from the registry or SAM by anyone with file access.', 'Delete the DefaultUserName/DefaultPassword values under HKLM\\...\\Winlogon')
    : finding('autologon', 'ok', 'Automatic logon', 'not configured', 'No stored unattended-logon credential.'));

  // 13. remote assistance
  f.push(remAssist && regNum(remAssist) === 1
    ? finding('remassist', 'medium', 'Remote Assistance enabled', 'AllowToGetHelp = 1', 'Lets a helper drive this desktop interactively after an invitation file is accepted.', 'Turn off: System Properties > Remote > uncheck Allow assistance')
    : finding('remassist', 'ok', 'Remote Assistance', 'not enabled', 'No interactive assistance channel.'));

  // 14. remote registry
  f.push(rmrSvc && rmrSvc.running
    ? finding('remreg', 'high', 'Remote Registry service running', rmrSvc.name, 'Remote Registry allows arbitrary registry reads and writes over the network, which is a standard privilege-escalation primitive.', 'Stop and disable: net stop RemoteRegistry / sc config RemoteRegistry start= disabled')
    : finding('remreg', 'ok', 'Remote Registry service', rmrSvc ? rmrSvc.name : 'not found', 'Not running.'));

  // 15. USB storage
  const usbStart = usb ? regNum(usb) : null;
  f.push(usbStart !== 0
    ? finding('usb', 'low', 'USB mass storage permitted', 'USBSTOR start = ' + (usbStart == null ? 'default' : usbStart), 'Removable devices can mount and copy data, which is the usual first step of a physical-access attack.', 'Restrict the policy: Computer Configuration > Administrative Templates > System > Removable Storage > Deny all removable storage')
    : finding('usb', 'ok', 'USB mass storage', 'blocked', 'Removable storage is denied by policy.'));

  // 16. listening services
  if (conns && Array.isArray(conns.listenPorts)) {
    const all = conns.listenPorts;
    const risky = all.filter((p) => RISKY_LOCAL_PORTS.has(p));
    f.push(risky.length
      ? finding('localports', 'medium', 'Sensitive local services listening', risky.join(', ') + '  (' + all.length + ' listening in total)',
        'These ports accept connections from anything that can reach this host: ' + risky.map((p) => RISKY_LOCAL_PORTS.get(p)).join(', ') + '. Reachability depends on the firewall profile, currently ' + curName + '.',
        'Stop what you do not need (net stop <service>), or add a Windows Firewall inbound rule scoped to your own subnet.')
      : finding('localports', 'ok', 'Listening services', all.length + ' port(s), none in the sensitive set', 'No high-risk local services detected.'));
  }

  // 17. patch level
  if (build) {
    const b = build.raw || build.data;
    const u = ubr ? regNum(ubr) : null;
    f.push(finding('build', 'info', 'OS build', b + (u != null ? '.' + u : ''), 'Patch level identifies which cumulative updates are installed. Newer is better; check against the current Windows 11 release.'));
  }

  return {
    id: 'host', title: 'HOST HARDENING', icon: 'shield',
    subtitle: 'Windows configuration posture of this machine',
    findings: f,
  };
}
const RISKY_LOCAL_PORTS = new Map([
  [21, 'ftp (cleartext)'], [22, 'ssh'], [23, 'telnet (cleartext)'], [25, 'smtp'],
  [135, 'RPC endpoint mapper'], [139, 'NetBIOS session'], [445, 'SMB file sharing'],
  [3306, 'MySQL'], [3389, 'RDP'], [5432, 'PostgreSQL'], [5900, 'VNC'],
  [5985, 'WinRM'], [5986, 'WinRM (TLS)'], [6379, 'Redis'], [9200, 'Elasticsearch'],
  [11211, 'memcached'], [27017, 'MongoDB'], [7547, 'TR-069/CWMP'],
]);

/* ---- WI-FI: link-layer posture ---- */
const VENDOR_SSID = /(^|[\s_-])(tp-?link|netgear|d-?link|huawei|zte|huawei_|zyxel|technicolor|arris|linksys|tenda|realtek|mikrotik|ubiquiti|asus|belkin|tenda|hp-?print|xerox|canon|brother|epson|android|iphone|galaxy|redmi|tecno|itel|infinix|oppo|vivo|realme)([\s_-]|$)/i;
function auditWifi(networks, connected, iface) {
  const f = [];
  const c = connected || {};
  const sec = (c.security || '').toUpperCase();
  const cipher = c.cipher || '';

  if (/WEP/.test(sec)) {
    f.push(finding('wifi-cipher', 'critical', 'WEP encryption', sec, 'WEP can be cracked in minutes from a single captured frame. Anyone on radio range can read your traffic.', 'Reconfigure the AP for WPA2-AES or WPA3'));
  } else if (/TKIP/.test(sec + cipher) || /WPA2/.test(sec) && /TKIP/.test(cipher)) {
    f.push(finding('wifi-cipher', 'high', 'WPA with TKIP', sec + ' / ' + cipher, 'TKIP is a compatibility shim over the broken WEP design and has known weaknesses. It is the cipher chosen to keep old devices working.', 'Switch the AP to WPA2-AES/CCMP or WPA3'));
  } else if (/WPA3/.test(sec)) {
    f.push(finding('wifi-cipher', 'ok', 'WPA3 encryption', sec + (cipher ? ' / ' + cipher : ''), 'The strongest consumer Wi-Fi standard, with per-session keys and forward secrecy.'));
  } else if (/WPA2/.test(sec)) {
    f.push(finding('wifi-cipher', 'ok', 'WPA2 encryption', sec + (cipher ? ' / ' + cipher : ''), 'Acceptable encryption. Stronger if the passphrase is long.'));
  } else if (/WPA\b/.test(sec)) {
    f.push(finding('wifi-cipher', 'high', 'WPA (legacy)', sec, 'Original WPA used TKIP and is considered broken. Should be replaced with WPA2 or WPA3.', 'Reconfigure the AP for WPA2-AES or WPA3'));
  } else if (/OPEN|NONE/.test(sec)) {
    f.push(finding('wifi-cipher', 'critical', 'Open / unauthenticated network', sec || 'open', 'No encryption and no passphrase. Anyone in radio range can read and modify all traffic, and impersonate the access point.', 'Enable WPA2/WPA3 with a strong passphrase on the AP'));
  } else {
    f.push(finding('wifi-cipher', 'info', 'Wi-Fi security', sec || 'unknown', 'Security mode could not be determined.'));
  }

  // passphrase strength is not directly observable; infer from SSID hints only
  if (VENDOR_SSID.test(c.ssid || '')) {
    f.push(finding('wifi-ssid', 'low', 'SSID reveals the device', c.ssid, 'Vendor-branded SSIDs tell an attacker which model to target and which default passwords to try first.', 'Rename the network to something neutral, and disable WPS'));
  } else {
    f.push(finding('wifi-ssid', 'ok', 'SSID', c.ssid || '\u2014', 'Name does not advertise the hardware vendor.'));
  }

  // channel congestion
  const ch = String(c.channel || '');
  const sameCh = (networks || []).filter((n) => String(n.channel) === ch && n.ssid && n.ssid !== c.ssid);
  const sameChAll = (networks || []).filter((n) => String(n.channel) === ch);
  const chLabel = 'channel ' + ch + (c.band ? ' (' + c.band + ')' : '');
  if (sameChAll.length > 4) {
    f.push(finding('wifi-congest', 'medium', 'Channel congestion', chLabel + ' shared by ' + sameChAll.length + ' APs', 'Co-channel neighbours force the radio to defer, cutting throughput and raising retry rates.', 'Move to a quieter channel in the 2.4 GHz band (1/6/11 only), or use 5/6 GHz where available'));
  } else {
    f.push(finding('wifi-congest', 'ok', 'Channel utilisation', chLabel + ', ' + sameChAll.length + ' nearby AP(s)', 'Channel is not heavily contended.'));
  }

  // rogue / evil-twin: same SSID, different BSSID
  const twins = (networks || []).filter((n) => n.ssid === c.ssid && n.bssid && c.bssid && n.bssid !== c.bssid);
  f.push(twins.length
    ? finding('wifi-twin', 'medium', 'Duplicate SSID detected', c.ssid + ' on ' + (twins.length + 1) + ' BSSIDs', 'More than one access point advertises this network name. That is normal for mesh and extender setups, but it is also exactly what an evil-twin attack looks like. Confirm the extra BSSID belongs to your own equipment.', 'Check the BSSID list in the Wi-Fi panel against your router/mesh nodes')
    : finding('wifi-twin', 'ok', 'Single BSSID for this SSID', c.bssid || '\u2014', 'No competing access point advertising the same name.'));

  // signal
  const dbm = c.dbm;
  if (isFinite(dbm)) {
    f.push(dbm < -75
      ? finding('wifi-signal', 'low', 'Weak signal', dbm + ' dBm', 'A very weak link is easy to influence: an attacker nearby can force a deauth flood and capture the handshake when you reconnect.', 'Move closer to the AP, or add an access point')
      : finding('wifi-signal', 'ok', 'Signal strength', dbm + ' dBm', 'Strong enough that deauth-based capture is impractical at distance.'));
  }

  // WPS / band
  f.push(finding('wifi-band', 'info', 'Radio band', (c.band || '?') + ' / channel ' + (c.channel || '?') + (c.radioType ? ' / ' + c.radioType : ''), '2.4 GHz reaches further but is crowded and lower throughput; 5/6 GHz is faster and shorter range.'));

  return { id: 'wifi', title: 'WI-FI SECURITY', icon: 'wifi', subtitle: 'Link-layer encryption and radio posture of ' + (c.ssid || 'current AP'), findings: f };
}

/* ---- GATEWAY: local configuration exposure of the default router ---- */
const GW_RISK_PORTS = [
  [21, 'ftp', 'critical', 'Router FTP service is open — many ISP routers ship with an FTP daemon for firmware update.'],
  [22, 'ssh', 'high', 'SSH on a consumer router is rarely hardened and is a favourite brute-force target.'],
  [23, 'telnet', 'critical', 'Telnet on a router is the single most common compromise path. Credentials travel in cleartext and defaults are frequently unchanged.'],
  [7547, 'tr-069/cwmp', 'high', 'TR-069 WAN management is a widely automated remote-compromise surface (the vector behind several large ISP router worms).'],
  [37215, 'huawei-hg532', 'critical', 'Port 37215 on Huawei home gateways has a well-known unauthenticated remote code execution flaw.'],
  [52869, 'upnp-realtek', 'high', 'Realtek SDK miniigd UPnP service. Exposed instances allow unauthenticated remote command execution.'],
  [80, 'http-admin', 'medium', 'Plaintext web management. Sessions and credentials are visible to anyone on the path.'],
  [443, 'https-admin', 'info', 'Encrypted web management interface.'],
  [8080, 'http-admin-alt', 'medium', 'Secondary web management port.'],
  [8443, 'https-admin-alt', 'info', 'Secondary encrypted management port.'],
  [1900, 'ssdp-upnp', 'medium', 'SSDP/UPnP. If the router maps ports on request, any program on this LAN can open a hole to the internet.'],
  [5357, 'wsman', 'high', 'WS-Management. Remote PowerShell-style management, usually unintended on a home router.'],
];
const GW_BRANDS = [
  [/zte/i, 'ZTE'], [/huawei/i, 'Huawei'], [/fiberhome/i, 'FiberHome'], [/zte/i, 'ZTE'],
  [/tp-?link|archer/i, 'TP-Link'], [/netgear/i, 'Netgear'], [/d-?link/i, 'D-Link'],
  [/tenda/i, 'Tenda'], [/technicolor|media.?tek/i, 'Technicolor'], [/arris/i, 'Arris'],
  [/nokia/i, 'Nokia'], [/linksys/i, 'Linksys'], [/realtek/i, 'Realtek'], [/zyxel/i, 'Zyxel'],
  [/opengn|openwrt/i, 'OpenWrt'], [/mikrotik/i, 'MikroTik'],
];
function identifyBrand(text) {
  for (const [re, name] of GW_BRANDS) if (re.test(text)) return name;
  return null;
}

async function auditGateway() {
  const f = [];
  let info = null;
  try { info = await netInfo(); } catch { /* ignore */ }
  const gw = info && info.gateway;
  if (!gw) {
    return { id: 'gateway', title: 'GATEWAY / ROUTER', icon: 'router', subtitle: 'No default gateway detected', findings: [finding('gw', 'unknown', 'Default gateway', 'not found', 'Cannot audit the router without a default route.')] };
  }
  const localBase = info.ipv4 ? info.ipv4.split('.').slice(0, 3).join('.') : null;

  const ports = GW_RISK_PORTS.filter((p) => p[2] !== null).map((p) => p[0]);
  const scan = await portScan(gw, ports, 800).catch(() => ({ open: [] }));
  const open = scan.open || [];
  const fmap = new Map(GW_RISK_PORTS.filter((p) => p[2]).map((p) => [p[0], p]));

  // identify the admin UI
  let brand = null, title = null;
  for (const o of open.filter((x) => [80, 443, 8080, 8443].includes(x.port))) {
    if (o.banner) {
      const bm = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(o.banner);
      if (bm) { title = bm[1].replace(/\s+/g, ' ').trim().slice(0, 80); brand = brand || identifyBrand(o.banner); }
      brand = brand || identifyBrand(o.banner);
    }
  }

  const openSet = new Set(open.map((o) => o.port));
  for (const o of open) {
    const meta = fmap.get(o.port);
    if (!meta) continue;
    f.push(finding('gw-' + o.port, meta[2], 'Port ' + o.port + ' open — ' + meta[1], 'latency ' + o.latency + ' ms', meta[3], o.port === 23 || o.port === 21
      ? 'Disable telnet/ftp in the router admin page; use the web UI on the LAN only'
      : o.port === 7547 || o.port === 37215 || o.port === 52869
        ? 'Contact your ISP, or update the router firmware. These are remote-compromise surfaces with published, unpatched flaws.'
        : 'Disable the service in the router admin page, and confirm management is not exposed from the WAN side.'));
  }

  // absent-but-should-be-checked findings
  if (!openSet.has(23) && !openSet.has(21)) {
    f.push(finding('gw-telnet-absent', 'ok', 'No telnet/ftp on the router', 'ports 23/21 closed', 'The router does not offer a cleartext remote-login service.'));
  }
  if (open.length === 0) {
    f.push(finding('gw-open', 'ok', 'No management ports answered', 'no open admin ports', 'The router did not respond on any known management port within the scan window.'));
  }
  f.push(finding('gw-admin', 'info',
    'Management interface reachable from LAN',
    open.filter((o) => [80, 443, 8080, 8443].includes(o.port)).map((o) => o.port).join(', ') || 'none found',
    'Expected on your own network. The question is whether the same interface is also reachable from the internet, which cannot be determined from inside the LAN.',
    'In the router admin page, confirm "Remote management / WAN access" is disabled'));
  f.push(finding('gw-brand', 'info', 'Router identity',
    [brand, title].filter(Boolean).join(' — ') || 'not identified',
    brand ? 'Recognised hardware family. Known vulnerabilities for this family can be checked against the vendor advisory before you rely on it.' : 'Firmware banner did not reveal a vendor.',
    'Update the router firmware to the latest release published by your ISP'));
  f.push(finding('gw-dns', info.dns && info.dns.includes(gw) ? 'low' : 'info',
    'Router is the DNS resolver', (info.dns || []).join(', '),
    'When the router resolves DNS, compromising the router silently redirects every site you visit. It also means the router sees the full list of domains you look up.',
    'Consider a DoH resolver (Cloudflare, Quad9) to bypass the router for DNS'));
  f.push(finding('gw-scope', 'ok', 'Scan scope', 'TCP connect to ' + gw + ' only',
    'Only the default gateway was probed, using TCP connection attempts. No payloads were sent and no credentials were tested.'));

  return { id: 'gateway', title: 'GATEWAY / ROUTER', icon: 'router', subtitle: 'Configuration exposure of ' + gw, gateway: gw, brand, findings: f };
}

/* ---- LAN: risky service exposure across the local /24 ---- */
const LAN_RISK_PORTS = [
  [21, 'ftp', 'high', 'Cleartext file transfer.'],
  [22, 'ssh', 'medium', 'Remote shell.'],
  [23, 'telnet', 'high', 'Cleartext remote shell; default credentials are common.'],
  [25, 'smtp', 'low', 'Mail transfer agent reachable from the LAN.'],
  [53, 'dns', 'medium', 'DNS service reachable from the LAN.'],
  [80, 'http', 'medium', 'Web management or application.'],
  [139, 'netbios', 'medium', 'NetBIOS name service.'],
  [443, 'https', 'medium', 'Web service.'],
  [445, 'smb', 'high', 'File and printer sharing.'],
  [3389, 'rdp', 'high', 'Remote Desktop.'],
  [5900, 'vnc', 'high', 'VNC remote screen sharing.'],
  [5985, 'winrm', 'high', 'Windows Remote Management.'],
  [6379, 'redis', 'high', 'Redis, frequently unauthenticated.'],
  [8080, 'http-alt', 'medium', 'Alternate web service.'],
  [9100, 'printer', 'low', 'Raw print service.'],
];
async function auditLan() {
  const t0 = Date.now();
  const info = await netInfo();
  const base = info.ipv4 ? info.ipv4.split('.').slice(0, 3).join('.') : null;
  if (!base || !info.prefix || info.prefix > 24) {
    return { id: 'lan', title: 'LAN EXPOSURE', icon: 'lan', subtitle: 'Scope refused: subnet is not a /24 or smaller', findings: [finding('lan-scope', 'unknown', 'Subnet too large to sweep safely', base + '/' + info.prefix, 'This tool limits sweeps to /24 and smaller.')] };
  }
  const ports = LAN_RISK_PORTS.map((p) => p[0]);
  const CONC = 96;
  const hits = [];
  let idx = 0;
  const hostMap = new Map();
  const list = [];
  for (let i = 1; i <= 254; i++) list.push(base + '.' + i);
  async function worker() {
    while (idx < list.length) {
      const ip = list[idx++];
      for (const port of ports) {
        const ms = await tcpPing(ip, port, 500);
        if (ms != null) {
          if (!hostMap.has(ip)) { hostMap.set(ip, []); list2push(hostMap.get(ip), port, ms); }
          else hostMap.get(ip).push({ port, ms });
        }
      }
    }
  }
  function list2push(arr, port, ms) { arr.push({ port, ms }); }
  await Promise.all(Array.from({ length: CONC }, worker));

  // merge with ARP for names
  const arp = await run('arp.exe', ['-a'], { timeout: 10000 });
  const macFor = new Map();
  for (const l of (arp.stdout || '').split(/\r?\n/)) {
    const m = /(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})/i.exec(l);
    if (m) macFor.set(m[1], m[2].toLowerCase().replace(/-/g, ':'));
  }

  const pmeta = new Map(LAN_RISK_PORTS.map((p) => [p[0], p]));
  for (const [ip, arr] of hostMap) {
    arr.sort((a, b) => a.port - b.port);
    const isGw = ip === info.gateway;
    const isSelf = ip === info.ipv4;
    for (const h of arr) {
      const meta = pmeta.get(h.port);
      hits.push({
        ip, mac: macFor.get(ip) || '', port: h.port, service: meta ? meta[1] : 'unknown',
        sev: meta ? meta[2] : 'info', detail: meta ? meta[3] : '', latency: Math.round(h.ms),
        role: isGw ? 'gateway' : isSelf ? 'self' : 'host',
      });
    }
  }
  const riskRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  hits.sort((a, b) => (riskRank[a.sev] - riskRank[b.sev]) || (a.ip.localeCompare(b.ip)) || (a.port - b.port));

  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const h of hits) if (counts[h.sev] != null) counts[h.sev]++;
  const highRisky = hits.filter((h) => h.sev === 'high');
  const f = [];
  f.push(finding('lan-scan', 'info', 'Sweep performed', hits.length + ' service(s) across ' + hostMap.size + ' live host(s)',
    '254 addresses x ' + ports.length + ' TCP ports, connect-only, ' + Math.round((Date.now() - t0) / 100) / 10 + 's. Nothing was sent beyond this subnet and no credentials were tested.',
    ''));
  if (highRisky.length) {
    f.push(finding('lan-high', 'high', highRisky.length + ' high-risk service(s) reachable',
      highRisky.map((h) => h.ip + ':' + h.port + ' ' + h.service).join(', '),
      'These services accept connections from anywhere on the LAN. A device already on the network — a guest phone, a compromised smart TV, a compromised IoT device — can use them to move laterally or to attack stored credentials.',
      'On each host: disable the service if unneeded, or restrict it with a Windows Firewall inbound rule limited to your own subnet/IP.'));
  } else {
    f.push(finding('lan-high', 'ok', 'No high-risk services reachable', 'none found', 'Nothing in the cleartext-shell or file-sharing category answered.'));
  }
  const med = hits.filter((h) => h.sev === 'medium');
  if (med.length) f.push(finding('lan-med', 'medium', med.length + ' medium-risk service(s)', med.slice(0, 8).map((h) => h.ip + ':' + h.port).join(', ') + (med.length > 8 ? ' …' : ''), 'Commonly used for administration or file sharing. Confirm each is intended to be reachable from your network.', 'Close or restrict what you do not need.'));
  if (counts.low || counts.info) f.push(finding('lan-low', 'info', counts.low + ' low / ' + counts.info + ' informational', '', 'Lower-impact findings, listed in the table below.', ''));

  return {
    id: 'lan', title: 'LAN EXPOSURE', icon: 'lan', subtitle: 'Service exposure across ' + base + '.0/24',
    base, hosts: hostMap.size, hits, counts, findings: f,
  };
}

/* ---- aggregate ---- */
function scoreOf(sections) {
  let penalty = 0;
  const summary = { critical: 0, high: 0, medium: 0, low: 0, ok: 0, unknown: 0, info: 0 };
  for (const s of sections) for (const f of s.findings) {
    summary[f.sev] = (summary[f.sev] || 0) + 1;
    penalty += SEV_W[f.sev] || 0;
  }
  const score = Math.max(0, 100 - penalty);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  const parts = [];
  if (summary.critical) parts.push(summary.critical + ' critical');
  if (summary.high) parts.push(summary.high + ' high');
  if (summary.medium) parts.push(summary.medium + ' medium');
  if (summary.low) parts.push(summary.low + ' low');
  return { score, grade, summary, penalty, headline: parts.length ? parts.join(', ') + ' severity finding' + (parts.length > 1 ? 's' : '') : 'no actionable findings' };
}

function crackabilityVerdict(sections, s) {
  const all = sections.flatMap((x) => x.findings);
  const host = sections.find((x) => x.id === 'host') || { findings: [] };
  const lan = sections.find((x) => x.id === 'lan') || { findings: [], hits: [] };
  const gw = sections.find((x) => x.id === 'gateway') || { findings: [] };
  const bad = (sec, id) => sec.findings.some((f) => f.id === id && f.sev !== 'ok' && f.sev !== 'info' && f.sev !== 'unknown');

  const weakPw = bad(host, 'pwlen') || bad(host, 'lockout');
  const routerShell = gw.findings.some((f) => f.id === 'gw-23' || f.id === 'gw-21');
  const routerMgmt = gw.findings.some((f) => ['gw-7547', 'gw-37215', 'gw-52869', 'gw-5357'].includes(f.id));
  const selfExposed = (lan.hits || []).some((h) => (h.role === 'self' || h.role === 'gateway') && h.sev === 'high');
  const lanExposed = (lan.hits || []).filter((h) => h.sev === 'high');
  const openWifi = bad({ findings: sections.find((x) => x.id === 'wifi').findings }, 'wifi-cipher');
  const noUac = bad(host, 'uac') || bad(host, 'fw');
  const remreg = bad(host, 'remreg') || bad(host, 'autologon');

  const ease = [];
  if (openWifi) ease.push('the wireless link itself is unauthenticated, so traffic is readable without touching the machine');
  if (routerShell) ease.push('the router offers a cleartext remote shell, so router credentials are guessable from the wire');
  if (routerMgmt) ease.push('the router exposes a remote-management port that is a known compromise vector');
  if (weakPw) ease.push('local accounts have no effective password length floor and no lockout, so guessing is unthrottled');
  if (lanExposed.length) ease.push(lanExposed.length + ' device(s) on this network expose a high-risk service (' + lanExposed.slice(0, 3).map((h) => h.ip + ':' + h.port).join(', ') + ')');
  if (selfExposed) ease.push('this host itself exposes a high-risk service to the LAN');
  if (noUac) ease.push('host protection is reduced (firewall or UAC disabled)');
  if (remreg) ease.push('a remote-administration primitive is enabled on the host');

  let level, levelSev, headline;
  if (ease.length >= 3) {
    level = 'Several independent weak points'; levelSev = 'high';
    headline = 'Not hardened. Someone already on this network would have multiple ways in.';
  } else if (ease.length === 2) {
    level = 'Two weak points'; levelSev = 'medium';
    headline = 'Two configurations together would make this straightforward to access from the network.';
  } else if (ease.length === 1) {
    level = 'One clear weak point'; levelSev = 'medium';
    headline = 'Mostly hardened, with one configuration that gives away access.';
  } else {
    level = 'No obvious weak point found'; levelSev = 'ok';
    headline = 'No configuration weakness that would make this straightforward to access was detected.';
  }
  const detail = ease.length
    ? 'What was found: ' + ease.join('; ') + '.'
    : 'Firewall, remote-access services, account policy and Wi-Fi encryption all pass. This audit inspects configuration only and never tests credentials, so a weak but well-hidden password would not be detected here.';
  return { level, sev: levelSev, headline, detail, weaknesses: ease.length, score: s.score, grade: s.grade };
}

async function auditAll() {
  const t0 = Date.now();
  const [host, wifiData, gwData, lanData] = await Promise.all([
    auditHost(),
    (async () => {
      try {
        const [nets, iface] = await Promise.all([scanWifi(false), wifiInterface()]);
        const conn = iface && iface.state === 'connected' ? iface : null;
        if (conn) { const hit = nets.find((n) => n.bssid === conn.bssid); if (hit) hit.connected = true; }
        return auditWifi(nets, conn, iface);
      } catch (e) { return { id: 'wifi', title: 'WI-FI SECURITY', icon: 'wifi', subtitle: 'unavailable', findings: [finding('wifi', 'unknown', 'Wi-Fi audit', 'error', String(e.message || e), '')] }; }
    })(),
    auditGateway(),
    auditLan(),
  ]);
  const sections = [host, wifiData, gwData, lanData];
  const s = scoreOf(sections);
  return {
    ok: true, at: new Date().toISOString(), elapsed: Date.now() - t0,
    ...s, sections, verdict: crackabilityVerdict(sections, s),
    scope: 'Local host configuration, the default gateway, and this /24. Connect-only probes. No credential testing, no exploitation.',
  };
}

module.exports = {
  install(ctx) { CTX = ctx; },
  locate,
  auditAll,
};
