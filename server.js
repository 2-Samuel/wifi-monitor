'use strict';
/* ============================================================
   NETRECON v2.1 — local backend
   Real network reconnaissance for Windows using only built-in tools.
   Binds to 127.0.0.1 only. No external dependencies.
   ============================================================ */

const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const net = require('net');
const dns = require('dns');
const { execFile } = require('child_process');

const HOST = '127.0.0.1';
const PORT = Number(process.env.PORT || 8787);
const ROOT = __dirname;
const REPORTS = path.join(ROOT, 'reports');

/* geolocation + security audit module, bound to the helpers below */
const auditApi = require('./audit.js');
auditApi.install({ run, cached, netInfo, scanWifi, wifiInterface, portScan, tcpPing, connections });

/* ============================================================
   process helpers
   ============================================================ */
function run(file, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(file, args, {
      windowsHide: true,
      maxBuffer: 12 * 1024 * 1024,
      timeout: opts.timeout || 30000,
      encoding: 'utf8',
    }, (err, stdout, stderr) => {
      resolve({ ok: !err, code: err && err.code, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

const cache = new Map();
async function cached(key, ttlMs, fn) {
  const hit = cache.get(key);
  if (hit && hit.pending) return hit.pending;
  const now = Date.now();
  if (hit && now - hit.at < ttlMs) return hit.val;
  const p = Promise.resolve().then(fn).then(
    (val) => { cache.set(key, { at: Date.now(), val }); return val; },
    (err) => { cache.delete(key); throw err; }
  );
  cache.set(key, { at: now, val: hit ? hit.val : null, pending: p });
  return p;
}
function dropCache(prefix) {
  for (const k of cache.keys()) if (k.startsWith(prefix)) cache.delete(k);
}

/* ============================================================
   parsers
   ============================================================ */
const SEC_MAP = [
  [/wpa3.*enterprise/i, 'WPA3-E'],
  [/wpa3/i, 'WPA3'],
  [/wpa2.*enterprise/i, 'WPA2-E'],
  [/wpa2|wpa2-psk/i, 'WPA2'],
  [/wpa-?psk|^wpa$/i, 'WPA'],
  [/wep/i, 'WEP'],
  [/open|none/i, 'OPEN'],
];

function normSecurity(auth, cipher) {
  const a = (auth || '').trim();
  for (const [re, label] of SEC_MAP) if (re.test(a)) {
    if (label === 'WPA2-E') return 'WPA2-E';
    return label;
  }
  return a ? a.toUpperCase().replace(/-PERSONAL$/, '') : 'OPEN';
}

/* Windows reports signal as a percentage. Map to dBm with the
   standard Windows curve: 0% -> -100 dBm, 100% -> -50 dBm.  */
function pctToDbm(pct) {
  const p = Math.max(0, Math.min(100, pct));
  return Math.round(p / 2 - 100);
}
function dbmToPct(dbm) {
  return Math.max(1, Math.min(100, Math.round((dbm + 100) * 2)));
}
function chanToFreq(ch) {
  if (!ch || ch <= 0) return null;
  if (ch === 14) return 2484;
  if (ch <= 13) return 2412 + (ch - 1) * 5;
  if (ch < 32) return null;
  return 5000 + ch * 5;
}
function bandOf(ch) {
  if (!ch) return '';
  if (ch <= 14) return '2.4 GHz';
  if (ch <= 196) return '5 GHz';
  return '6 GHz';
}
function freqLabel(ch) {
  const f = chanToFreq(ch);
  if (!f) return bandOf(ch) || '--';
  return (f >= 5905 ? '6 GHz' : f >= 5000 ? '5 GHz' : '2.4 GHz');
}
function prefixToMask(p) {
  const out = [];
  for (let i = 0; i < 4; i++) {
    const b = Math.max(0, Math.min(8, p - i * 8));
    out.push(256 - Math.pow(2, 8 - b));
  }
  return out.join('.');
}
function isPrivate(ip) {
  if (!ip) return false;
  if (ip.startsWith('127.') || ip === '::1') return true;
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

/* ---- netsh wlan show networks mode=bssid ---- */
async function scanWifi(force) {
  if (force) {
    await run('netsh', ['wlan', 'scan'], { timeout: 8000 });
    await new Promise((r) => setTimeout(r, 400));
  }
  const { stdout } = await run('netsh', ['wlan', 'show', 'networks', 'mode=bssid'], { timeout: 20000 });
  const lines = stdout.split(/\r?\n/);
  const aps = [];
  let cur = null;
  let curBssid = null;

  for (const raw of lines) {
    const line = raw.replace(/\t/g, '    ');
    let m = /^\s*SSID\s+(\d+)\s*:\s*(.*)$/.exec(line);
    if (m) {
      cur = { ssid: m[2].trim(), auth: '', cipher: '', bssids: [] };
      curBssid = null;
      aps.push(cur);
      continue;
    }
    if (!cur) continue;
    m = /^\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})/.exec(line);
    if (m) {
      curBssid = { bssid: m[1].toLowerCase(), signalPct: 0, channel: 0, radio: '' };
      cur.bssids.push(curBssid);
      continue;
    }
    m = /^\s*([A-Za-z][A-Za-z ()\/-]*?)\s*:\s*(.*?)\s*$/.exec(line);
    if (!m) continue;
    const key = m[1].trim().toLowerCase();
    const val = m[2].trim();
    if (key === 'authentication') cur.auth = val;
    else if (key === 'encryption') cur.cipher = val;
    else if (key === 'network type') cur.type = val;
    else if (curBssid) {
      if (key === 'signal') curBssid.signalPct = parseInt(val, 10) || 0;
      else if (key === 'channel') curBssid.channel = parseInt(val, 10) || 0;
      else if (key === 'band') curBssid.band = val;
      else if (key === 'radio type') curBssid.radio = val;
    }
  }

  return aps
    .map((ap) => {
      const best = ap.bssids.slice().sort((a, b) => b.signalPct - a.signalPct)[0] || {};
      const pct = best.signalPct || 0;
      const dbm = pctToDbm(pct);
      const ch = best.channel || 0;
      return {
        ssid: ap.ssid || '',
        hidden: !ap.ssid,
        signalPct: pct,
        dbm,
        channel: ch,
        freqMHz: chanToFreq(ch),
        frequency: freqLabel(ch),
        band: best.band || bandOf(ch),
        radio: best.radio || '',
        security: normSecurity(ap.auth, ap.cipher),
        auth: ap.auth || '',
        cipher: ap.cipher || '',
        bssid: best.bssid || '',
        bssids: ap.bssids.length,
      };
    })
    .filter((ap) => ap.bssid || ap.ssid)
    .sort((a, b) => b.signalPct - a.signalPct);
}

/* ---- netsh wlan show interfaces ---- */
async function wifiInterface() {
  const { stdout } = await run('netsh', ['wlan', 'show', 'interfaces'], { timeout: 15000 });
  const kv = {};
  for (const raw of stdout.split(/\r?\n/)) {
    const m = /^\s*([A-Za-z][A-Za-z ()#.\/-]*?)\s*:\s*(.*?)\s*$/.exec(raw);
    if (m) kv[m[1].trim().toLowerCase()] = m[2].trim();
  }
  if (!kv['state']) return null;
  const pct = parseInt(kv['signal'], 10) || 0;
  const ch = parseInt(kv['channel'], 10) || 0;
  const rx = parseFloat(kv['receive rate (mbps)']) || 0;
  const tx = parseFloat(kv['transmit rate (mbps)']) || 0;
  return {
    name: kv['name'] || 'Wi-Fi',
    description: kv['description'] || '',
    mac: (kv['physical address'] || '').toLowerCase(),
    state: kv['state'],
    ssid: kv['ssid'] || '',
    bssid: (kv['bssid'] || '').toLowerCase(),
    radioType: kv['radio type'] || '',
    auth: kv['authentication'] || '',
    cipher: kv['cipher'] || '',
    band: kv['band'] || bandOf(ch),
    channel: ch,
    freqMHz: chanToFreq(ch),
    frequency: freqLabel(ch),
    rxRate: rx,
    txRate: tx,
    signalPct: pct,
    dbm: pctToDbm(pct),
    security: normSecurity(kv['authentication'], kv['cipher']),
  };
}

/* ---- ipconfig /all + route print : no PowerShell, ~300 ms ---- */
function parseIpconfigAll(text) {
  const adapters = [];
  let cur = null, lastKey = null;
  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim()) continue;
    const head = /^([^\s].*?):\s*$/.exec(raw);
    if (head) {
      const label = head[1].trim();
      const name = label.includes(' adapter ') ? label.split(' adapter ').pop() : label;
      cur = { label, name, ipv4: '', mask: '', gateway: [], dns: [], mac: '', description: '', fields: {} };
      adapters.push(cur);
      lastKey = null;
      continue;
    }
    if (!cur) continue;
    const idx = raw.indexOf(' : ');
    if (idx > 0) {
      const key = raw.slice(0, idx).replace(/[.\s]+$/, '').trim().toLowerCase();
      const val = raw.slice(idx + 3).trim();
      lastKey = key;
      const prev = cur.fields[key];
      cur.fields[key] = prev === undefined ? val : (Array.isArray(prev) ? prev.concat(val) : [prev, val]);
    } else if (lastKey && /^\s{10,}\S/.test(raw)) {
      const prev = cur.fields[lastKey];
      cur.fields[lastKey] = Array.isArray(prev) ? prev.concat(raw.trim()) : [prev, raw.trim()];
    }
  }

  const flat = (v) => {
    if (v === undefined) return [];
    const arr = Array.isArray(v) ? v : [v];
    return arr.join(' ').split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
  };

  for (const a of adapters) {
    const f = a.fields;
    a.description = f['description'] || '';
    a.mac = (f['physical address'] || '').toLowerCase().replace(/-/g, ':');
    a.ipv4 = (flat(f['ipv4 address'])[0] || '').replace(/\(.*\)/, '');
    a.mask = (flat(f['subnet mask'])[0] || '');
    a.gateway = flat(f['default gateway']).filter((x) => /^\d+\.\d+\.\d+\.\d+$/.test(x));
    a.dns = flat(f['dns servers']).filter((x) => /^\d+\.\d+\.\d+\.\d+$/.test(x) || x.includes(':'));
    a.dhcp = /^yes$/i.test(f['dhcp enabled'] || '');
    a.mediastate = (f['media state'] || '').toLowerCase();
  }
  return adapters;
}
function maskToPrefix(mask) {
  if (!mask) return 0;
  return mask.split('.').reduce((a, o) => a + ((Number(o) || 0).toString(2).split('1').length - 1), 0);
}

async function netInfo() {
  const [{ stdout: ipcfg }, { stdout: route }] = await Promise.all([
    run('ipconfig', ['/all'], { timeout: 15000 }),
    run('route', ['print', '-4'], { timeout: 10000 }),
  ]);
  const adapters = parseIpconfigAll(ipcfg);

  let gw = '', ifaceIp = '';
  const m = /^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)\s+\d+/m.exec(route);
  if (m) { gw = m[1]; ifaceIp = m[2]; }

  const usable = adapters.filter((a) => a.ipv4 && !/media disconnected/i.test(a.mediastate));
  let pick = usable.find((a) => a.ipv4 === ifaceIp) ||
             usable.find((a) => /wi-?fi/i.test(a.name)) ||
             usable.find((a) => a.gateway.length) ||
             usable[0];

  if (!pick) {
    return {
      interface: 'none', description: '', mac: '', status: 'Down', linkSpeed: '',
      ipv4: '', prefix: 0, subnet: '', gateway: '', dns: [], adapters: adapters.length,
    };
  }
  if (!gw && pick.gateway.length) gw = pick.gateway[0];
  if (!pick.dns.length && gw) pick.dns = [];

  let linkSpeed = '';
  if (/wi-?fi/i.test(pick.label) || /wireless/i.test(pick.description)) {
    const w = await wifiInterface();
    if (w) linkSpeed = nz1(w.rxRate) + ' / ' + nz1(w.txRate) + ' Mbps';
  }

  return {
    interface: pick.name,
    label: pick.label,
    description: pick.description,
    mac: pick.mac,
    status: pick.mediastate ? 'Disconnected' : 'Up',
    linkSpeed,
    dhcp: !!pick.dhcp,
    ipv4: pick.ipv4,
    prefix: maskToPrefix(pick.mask) || 24,
    subnet: pick.mask || '',
    gateway: gw || (pick.gateway[0] || ''),
    dns: pick.dns,
    adapters: adapters.length,
    adapterList: adapters.filter((a) => a.ipv4).map((a) => ({ name: a.name, ipv4: a.ipv4, description: a.description })),
  };
}
const nz1 = (n) => (n == null || !isFinite(n) ? 0 : Math.round(n * 10) / 10);

/* ---- netstat -e : cumulative, system-wide interface counters ---- */
function parseNetstatE(text) {
  const num = (re) => { const m = re.exec(text); return m ? Number(m[1]) : null; };
  return {
    rxBytes: num(/^\s*Bytes\s+(\d+)\s+(\d+)/m) ,
    txBytes: (() => { const m = /^\s*Bytes\s+\d+\s+(\d+)/m.exec(text); return m ? Number(m[1]) : null; })(),
    rxPackets: (() => { const m = /^\s*Unicast packets\s+(\d+)\s+(\d+)/m.exec(text); return m ? Number(m[1]) : null; })(),
    txPackets: (() => { const m = /^\s*Unicast packets\s+\d+\s+(\d+)/m.exec(text); return m ? Number(m[1]) : null; })(),
    discards: (() => { const m = /^\s*Discards\s+(\d+)\s+(\d+)/m.exec(text); return m ? Number(m[1]) : null; })(),
    errors: (() => { const m = /^\s*Errors\s+(\d+)\s+(\d+)/m.exec(text); return m ? Number(m[1]) : null; })(),
  };
}

let lastCounters = null;
async function liveStats() {
  const { stdout } = await run('netstat', ['-e'], { timeout: 8000 });
  const c = parseNetstatE(stdout);
  const now = Date.now();
  let rates = { rxBps: 0, txBps: 0, rxPps: 0, txPps: 0, span: 0 };
  if (lastCounters && c.rxBytes != null) {
    const dt = (now - lastCounters.at) / 1000;
    if (dt > 0.05 && dt < 60) {
      const d = (a, b) => (a == null || b == null ? 0 : Math.max(0, a - b));
      rates = {
        rxBps: d(c.rxBytes, lastCounters.rxBytes) / dt,
        txBps: d(c.txBytes, lastCounters.txBytes) / dt,
        rxPps: d(c.rxPackets, lastCounters.rxPackets) / dt,
        txPps: d(c.txPackets, lastCounters.txPackets) / dt,
        span: dt,
      };
    }
  }
  lastCounters = { at: now, ...c };
  return { counters: c, rates, source: 'netstat -e (system-wide)' };
}

/* ---- netstat -ano : connections ---- */
function parseConnections(text) {
  let tcp = 0, udp = 0, listening = 0, established = 0;
  const peers = new Map();
  const listenPorts = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\S+)?/i.exec(line);
    if (!m) continue;
    const proto = m[1].toUpperCase();
    const state = (m[4] || '').toUpperCase();
    if (proto === 'TCP') {
      if (state === 'LISTENING') {
        listening++;
        const lp = Number((m[2].match(/:(\d+)$/) || [])[1]);
        if (lp) listenPorts.push(lp);
      }
      else if (state === 'ESTABLISHED') {
        established++;
        const p = m[3];
        const ip = p.replace(/:\d+$/, '');
        if (ip && !isPrivate(ip) && ip !== '0.0.0.0' && ip !== '*') {
          peers.set(ip, (peers.get(ip) || 0) + 1);
        }
      }
      tcp++;
    } else udp++;
  }
  return {
    tcp, udp, listening, established,
    listenPorts: [...new Set(listenPorts)].sort((a, b) => a - b),
    total: tcp + udp,
    topPeers: [...peers.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([ip, n]) => ({ ip, n })),
  };
}
async function connections() {
  const { stdout } = await run('netstat', ['-ano'], { timeout: 15000 });
  return parseConnections(stdout);
}

/* ---- arp -a ---- */
const OUI = {
  '00:11:22': 'Router/Gateway', 'e4:b2:84': 'Router/Gateway', '14:4f:8a': 'Intel',
  '00:0c:29': 'VMware', '08:00:27': 'VirtualBox', '52:54:00': 'QEMU/KVM',
  'b8:27:eb': 'Raspberry Pi', 'dc:a6:32': 'Raspberry Pi', 'f4:f5:d8': 'Google',
  '00:1b:63': 'Apple', '3c:07:54': 'Apple', 'a4:c3:61': 'Apple', 'd0:81:7a': 'Apple',
  '00:1e:c2': 'Apple', 'ac:bc:32': 'Apple', 'f0:18:98': 'Apple', '7c:d1:c3': 'Apple',
  '34:97:f6': 'ASUS', '50:46:5d': 'ASUS', '9c:5c:8e': 'ASUS', '2c:56:dc': 'ASUS',
  'e6:b2:84': 'Android/Phone', 'aa:bb:cc': 'Virtual Device',
  '00:17:88': 'Philips Hue', '44:65:0d': 'Amazon', 'fc:65:de': 'Amazon',
  '30:fd:38': 'Google Nest', '1c:f2:9a': 'Google Nest',
  'c0:56:27': 'Belkin', '00:24:e4': 'Withings',
};
function ouiName(mac) {
  const p = (mac || '').slice(0, 8).toLowerCase();
  return OUI[p] || null;
}
function parseArp(text) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)/.exec(line);
    if (!m) continue;
    const ip = m[1];
    const mac = m[2].toLowerCase().replace(/-/g, ':');
    const type = m[3].toLowerCase();
    if (mac === 'ff:ff:ff:ff:ff:ff') continue;
    if (/^01:00:5e/.test(mac) || /^33:33/.test(mac)) continue;
    const a = Number(ip.split('.')[0]);
    if (a >= 224) continue;
    out.push({ ip, mac, type, vendor: ouiName(mac), randomMac: isRandomMac(mac) });
  }
  return out;
}
/* Bit 1 of the first octet set = locally administered = MAC randomization
   (typical of modern phones/tablets). No vendor can be looked up. */
function isRandomMac(mac) {
  const first = parseInt((mac || '').slice(0, 2), 16);
  return Number.isFinite(first) && (first & 0x02) === 0x02;
}
function aliveProbe(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let sock;
    try { sock = net.connect({ host, port }); } catch { return resolve(false); }
    let done = false;
    const fin = (v) => { if (done) return; done = true; try { sock.destroy(); } catch { /* ignore */ } resolve(v); };
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => fin(true));
    sock.on('timeout', () => fin(false));
    sock.on('error', (e) => fin(!!e && (e.code === 'ECONNREFUSED' || e.code === 'ECONNRESET' || e.code === 'EACCES' || e.code === 'EPERM')));
  });
}

/* Sweep the local /24 so the ARP cache reflects reality.
   Scoped to private subnets only, max /24. */
async function arpSweep() {
  const info = await netInfo();
  const ip = info.ipv4;
  if (!ip || !isPrivate(ip)) return { error: 'refused', message: 'local interface is not on a private subnet' };
  if (info.prefix && info.prefix < 24) return { error: 'refused', message: 'subnet larger than /24 is not swept' };

  const base = ip.split('.').slice(0, 3).join('.');
  const hosts = [];
  for (let i = 1; i <= 254; i++) hosts.push(base + '.' + i);

  let idx = 0;
  const CONC = 160;
  async function worker() {
    while (idx < hosts.length) {
      const h = hosts[idx++];
      const up = await aliveProbe(h, 80, 180);
      if (!up) await aliveProbe(h, 443, 160);
    }
  }
  await Promise.all(Array.from({ length: CONC }, worker));
  await new Promise((r) => setTimeout(r, 350));
  return devices();
}

async function devices() {
  const [{ stdout }, info] = await Promise.all([run('arp', ['-a'], { timeout: 8000 }), netInfo()]);
  const gw = info.gateway;
  const self = info.ipv4;

  const localBase = self ? self.split('.').slice(0, 3).join('.') : null;

  const list = parseArp(stdout).filter((d) => {
    if (!localBase) return true;
    return d.ip.split('.').slice(0, 3).join('.') === localBase || d.ip === gw;
  });

  const named = list.map((d) => {
    let name = d.vendor;
    if (d.ip === gw) name = 'Router / Gateway';
    else if (d.ip === self) name = 'This Device';
    else if (d.ip === localBase + '.255') name = 'Broadcast';
    else if (!name) name = 'host .' + d.ip.split('.').pop();
    else name = d.vendor + ' .' + d.ip.split('.').pop();
    if (d.randomMac && d.ip !== gw && d.ip !== self) name = 'phone .' + d.ip.split('.').pop();
    return {
      ip: d.ip, mac: d.mac,
      name,
      role: d.ip === gw ? 'gateway' : d.ip === self ? 'self' : 'host',
      status: 'Online',
      type: d.type,
      vendor: d.vendor || '',
      randomMac: !!d.randomMac,
    };
  });

  // resolve PTR names in parallel for a nicer label (best effort)
  await Promise.all(named.map(async (d) => {
    if (d.role !== 'host') return;
    const ptr = await reverseDns(d.ip, 600);
    if (ptr && !/^\d+\.\d+\.\d+\.\d+$/.test(ptr) && !ptr.includes('in-addr.arpa')) {
      d.name = ptr.replace(/\.$/, '');
      d.ptr = true;
    }
  }));

  named.sort((a, b) => {
    const rank = (x) => (x.role === 'gateway' ? 0 : x.role === 'self' ? 1 : 2);
    return rank(a) - rank(b) || a.ip.localeCompare(b.ip, undefined, { numeric: true });
  });

  return {
    devices: named,
    arpEntries: list.length,
    subnet: localBase ? localBase + '.0/' + (info.prefix || 24) : null,
    scanned: localBase ? 254 : 0,
  };
}

/* ---- DNS ---- */
function resolverFor(server) {
  const r = new dns.promises.Resolver({ timeout: 3000, tries: 2 });
  if (server) r.setServers([server]);
  return r;
}
async function reverseDns(ip, timeoutMs) {
  try {
    const res = await Promise.race([
      dns.promises.reverse(ip),
      new Promise((_, rej) => setTimeout(() => rej(new Error('to')), timeoutMs || 1500)),
    ]);
    return Array.isArray(res) ? res[0] : null;
  } catch { return null; }
}
async function dnsLookup(domain, server) {
  const info = await cached('net', 5000, netInfo);
  const servers = server ? [server] : (info.dns.length ? info.dns : ['8.8.8.8']);
  const t0 = Date.now();
  let records = [], ttl = null, err = null;
  try {
    const r = resolverFor(servers[0]);
    const res = await r.resolve4(domain, { ttl: true });
    ttl = res.length ? res[0].ttl : null;
    records = res.map((x) => x.address);
  } catch (e) {
    err = e.code || e.message;
    try {
      const res = await dns.promises.resolve4(domain);
      records = res;
    } catch (e2) { /* ignore */ }
  }
  if (!records.length) {
    try {
      const res = await dns.promises.lookup(domain, { all: true });
      records = res.map((r) => r.address);
    } catch { /* ignore */ }
  }
  const ptr = records.length ? await reverseDns(records[0], 1200) : null;
  return {
    domain,
    records,
    ttl,
    resolver: servers[0],
    resolvers: servers,
    queryTime: Date.now() - t0,
    ptr,
    error: records.length ? null : (err || 'NXDOMAIN'),
  };
}

/* ---- traceroute ---- */
function parseTracert(text) {
  const hops = [];
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(\d+)\s+(.*)$/.exec(line);
    if (!m) continue;
    const n = Number(m[1]);
    const rest = m[2];
    if (n < 1 || n > 64) continue;
    if (/timed out|unreachable|error/i.test(rest)) {
      hops.push({ hop: n, ip: null, latency: null, timeout: true });
      continue;
    }
    const times = [...rest.matchAll(/(\d+)\s*ms/gi)].map((x) => Number(x[1]));
    const ipm = /((?:\d{1,3}\.){3}\d{1,3})/.exec(rest);
    hops.push({
      hop: n,
      ip: ipm ? ipm[1] : null,
      latency: times.length ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : null,
      best: times.length ? Math.min(...times) : null,
      timeout: false,
    });
  }
  return hops;
}
async function traceRoute(host, maxHops) {
  const info = await cached('net', 5000, netInfo);
  const t0 = Date.now();
  const target = await dns.promises.lookup(host, { family: 4 }).then((r) => r.address).catch(() => null);
  const { stdout } = await run('tracert', ['-4', '-d', '-w', '1200', '-h', String(Math.max(1, Math.min(30, maxHops || 12))), host], { timeout: 120000 });
  const hops = parseTracert(stdout);

  await Promise.all(hops.map(async (h) => {
    if (!h.ip) { h.host = 'Request timed out'; return; }
    if (info.gateway && h.ip === info.gateway) { h.host = '(gateway)'; return; }
    const ptr = await reverseDns(h.ip, 900);
    h.host = ptr ? ptr.replace(/\.$/, '') : '(no PTR record)';
  }));

  const reached = hops.filter((h) => h.ip).length;
  const lost = hops.filter((h) => h.timeout).length;
  return {
    target: host,
    targetIp: target,
    resolved: target,
    hops,
    reached,
    lost,
    totalMs: hops.reduce((a, h) => a + (h.latency || 0), 0),
    elapsed: Date.now() - t0,
    reachedTarget: hops.some((h) => h.ip === target),
    filtered: reached <= 1 && hops.length > 1,
  };
}

/* ---- TCP latency probe (ICMP is often filtered) ---- */
function tcpPing(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let sock;
    try {
      sock = net.connect({ host, port });
    } catch { return resolve(null); }
    const t0 = process.hrtime.bigint();
    let done = false;
    const fin = (v) => { if (done) return; done = true; try { sock.destroy(); } catch { /* ignore */ } resolve(v); };
    sock.setTimeout(timeoutMs || 1200);
    sock.on('connect', () => fin(Number(process.hrtime.bigint() - t0) / 1e6));
    sock.on('timeout', () => fin(null));
    sock.on('error', () => fin(null));
  });
}
async function latencyProbe(count) {
  const targets = [['1.1.1.1', 443], ['8.8.8.8', 443], ['9.9.9.9', 443]];
  let target = null;
  for (const t of targets) {
    const ms = await tcpPing(t[0], t[1], 1000);
    if (ms != null) { target = t; break; }
  }
  if (!target) {
    const info = await netInfo();
    if (info.gateway) target = [info.gateway, 80];
  }
  const samples = [];
  let sent = 0, got = 0;
  if (target) {
    for (let i = 0; i < (count || 8); i++) {
      sent++;
      const ms = await tcpPing(target[0], target[1], 1200);
      if (ms != null) { got++; samples.push(ms); }
    }
  }
  const avg = samples.length ? samples.reduce((a, b) => a + b, 0) / samples.length : null;
  let jitter = null;
  if (samples.length > 1) {
    let sum = 0;
    for (let i = 1; i < samples.length; i++) sum += Math.abs(samples[i] - samples[i - 1]);
    jitter = sum / (samples.length - 1);
  }
  return {
    target: target ? target[0] : null,
    latency: avg == null ? null : Math.round(avg),
    min: samples.length ? Math.round(Math.min(...samples)) : null,
    max: samples.length ? Math.round(Math.max(...samples)) : null,
    jitter: jitter == null ? null : Math.round(jitter * 10) / 10,
    loss: sent ? Math.round(((sent - got) / sent) * 1000) / 10 : null,
    samples: samples.length,
  };
}

/* ---- speed test via curl ---- */
const PAYLOAD = path.join(os.tmpdir(), 'netrecon-payload.bin');
function ensurePayload(bytes) {
  try {
    if (fs.existsSync(PAYLOAD) && fs.statSync(PAYLOAD).size === bytes) return PAYLOAD;
    fs.writeFileSync(PAYLOAD, Buffer.alloc(bytes, 0x5a));
  } catch { /* ignore */ }
  return PAYLOAD;
}
const CURL_FORMAT = '{"dl":%{size_download},"ul":%{size_upload},"t":%{time_total},"code":%{http_code}}';

async function curlRate(url, extra, timeoutMs, counter) {
  const args = ['-s', '-o', os.platform() === 'win32' ? 'NUL' : '/dev/null', '-w', CURL_FORMAT, '--max-time', String(Math.round(timeoutMs / 1000))];
  if (extra) args.push(...extra);
  args.push(url);
  const { stdout } = await run('curl.exe', args, { timeout: timeoutMs + 6000 });
  let j;
  try { j = JSON.parse(stdout.trim().split('\n').pop()); }
  catch { return { ok: false, bytes: 0, secs: 0, bps: 0 }; }
  const secs = Number(j.t) || 0;
  const bytes = Number(counter === 'ul' ? j.ul : j.dl) || 0;
  return { ok: true, bytes, secs, code: j.code, bps: secs > 0 ? bytes / secs : 0 };
}

let speedInFlight = null;
function speedTest() {
  if (speedInFlight) return speedInFlight;
  speedInFlight = (async () => {
    const t0 = Date.now();
    const [dl, lat] = await Promise.all([
      curlRate('https://speed.cloudflare.com/__down?bytes=50000000', null, 12000),
      latencyProbe(6),
    ]);
    const ul = await curlRate(
      'https://speed.cloudflare.com/__up',
      ['-X', 'POST', '-H', 'Content-Type: application/octet-stream', '--data-binary', '@' + ensurePayload(4 * 1024 * 1024)],
      15000,
      'ul'
    );
    const toMbps = (bps) => (isFinite(bps) && bps > 0 ? Math.round((bps * 8) / 1e6 * 100) / 100 : null);
    const dlMbps = toMbps(dl.bps);
    const ulMbps = toMbps(ul.bps);
    let error = null;
    if (!dl.ok || dl.bytes === 0) error = 'download probe returned no data';
    else if (ulMbps == null) error = 'upload probe returned no data';
    const partial = dl.bytes < 200 * 1024 && dlMbps != null && dlMbps < 5;
    return {
      download: dlMbps,
      upload: ulMbps,
      downloadBytes: dl.bytes,
      uploadBytes: ul.bytes,
      downloadSecs: Math.round(dl.secs * 100) / 100,
      uploadSecs: Math.round(ul.secs * 100) / 100,
      ping: lat.latency,
      jitter: lat.jitter,
      loss: lat.loss,
      pingMin: lat.min,
      pingMax: lat.max,
      pingTarget: lat.target,
      server: 'speed.cloudflare.com',
      duration: Date.now() - t0,
      at: new Date().toISOString(),
      partial,
      note: partial ? 'link transfer stalled — sample limited to ' + (dl.bytes / 1024).toFixed(1) + ' KB' : null,
      error,
    };
  })().finally(() => { setTimeout(() => { speedInFlight = null; }, 1000); });
  return speedInFlight;
}

/* ---- TCP connect port scan (authorized/private scope only) ---- */
const COMMON_PORTS = [
  [21, 'ftp'], [22, 'ssh'], [23, 'telnet'], [25, 'smtp'], [53, 'dns'], [67, 'dhcp'],
  [80, 'http'], [110, 'pop3'], [135, 'msrpc'], [139, 'netbios-ssn'], [143, 'imap'],
  [161, 'snmp'], [389, 'ldap'], [443, 'https'], [445, 'smb'], [465, 'smtps'],
  [514, 'syslog'], [587, 'submission'], [631, 'ipp'], [993, 'imaps'], [995, 'pop3s'],
  [1433, 'mssql'], [1900, 'ssdp'], [3306, 'mysql'], [3389, 'rdp'], [5353, 'mdns'],
  [5432, 'postgres'], [5900, 'vnc'], [6379, 'redis'], [7000, 'airplay'], [8008, 'http-alt'],
  [8080, 'http-proxy'], [8443, 'https-alt'], [8888, 'http-alt'], [9100, 'printer'],
  [32400, 'plex'], [49152, 'upnp'],
];
function grabBanner(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let sock;
    try { sock = net.connect({ host, port }); } catch { return resolve(null); }
    let done = false, buf = '';
    const fin = (v) => { if (done) return; done = true; try { sock.destroy(); } catch { /* ignore */ } resolve(v); };
    sock.setTimeout(timeoutMs);
    sock.on('connect', () => {
      try { sock.write('\r\n'); } catch { /* ignore */ }
    });
    sock.on('data', (d) => {
      buf += d.toString('latin1');
      if (buf.length > 160) buf = buf.slice(0, 160);
      fin(buf.replace(/[^\x20-\x7e]/g, ' ').trim().slice(0, 90));
    });
    sock.on('timeout', () => fin(buf.trim() || null));
    sock.on('error', () => fin(null));
    sock.on('close', () => fin(buf.trim() || null));
  });
}
async function portScan(host, ports, timeoutMs) {
  if (!isPrivate(host)) {
    return { error: 'refused', message: 'Only private/loopback targets are allowed by this tool.' };
  }
  const list = ports && ports.length ? ports.slice(0, 128) : COMMON_PORTS.map((p) => p[0]);
  const names = new Map(COMMON_PORTS);
  const open = [];
  const t0 = Date.now();
  const CONC = 48;
  let idx = 0;
  async function worker() {
    while (idx < list.length) {
      const port = list[idx++];
      const ms = await tcpPing(host, port, timeoutMs || 700);
      if (ms != null) {
        const banner = await grabBanner(host, port, 900);
        open.push({ port, service: names.get(port) || 'unknown', latency: Math.round(ms), banner: banner || null });
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONC, list.length) }, worker));
  open.sort((a, b) => a.port - b.port);
  return { host, scanned: list.length, open, openCount: open.length, elapsed: Date.now() - t0, fallbackOpen: null };
}

/* ============================================================
   background ping/quality sampler
   ============================================================ */
const quality = { history: [], last: null };
async function sampleQuality() {
  try {
    const l = await latencyProbe(4);
    l.at = Date.now();
    quality.last = l;
    quality.history.push(l);
    if (quality.history.length > 900) quality.history.shift();
    cache.set('quality', { at: Date.now(), val: l });
  } catch { /* ignore */ }
}
sampleQuality();
setInterval(sampleQuality, 5000);

/* ============================================================
   HTTP
   ============================================================ */
function send(res, code, body, type) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  res.writeHead(code, {
    'Content-Type': type || 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(buf);
}
const json = (res, obj, code) => send(res, code || 200, JSON.stringify(obj));

function safeHost(s) {
  return /^[a-zA-Z0-9._:-]{1,253}$/.test(s || '') ? s : null;
}

async function api(req, res, url) {
  const p = url.pathname;
  const qs = url.searchParams;

  if (p === '/api/bootstrap') {
    const [info, iface, nets, conns, live] = await Promise.all([
      netInfo(), wifiInterface(), scanWifi(false), connections().catch(() => null), liveStats().catch(() => null),
    ]);
    const connected = iface && iface.state === 'connected' ? iface : null;
    let networks = nets;
    if (connected) {
      const hit = networks.find((n) => n.bssid && n.bssid === connected.bssid) ||
                  networks.find((n) => n.ssid === connected.ssid);
      if (hit) hit.connected = true;
      else if (connected.ssid) networks = [{ ...connected, connected: true }, ...networks];
    }
    return json(res, {
      ok: true,
      host: { user: os.userInfo().username, os: os.type() + ' ' + os.release(), platform: os.platform(), hostname: os.hostname(), time: new Date().toISOString() },
      net: info,
      connected,
      networks,
      connections: conns,
      live,
      quality: quality.last,
      scanAt: new Date().toISOString(),
    });
  }

  if (p === '/api/scan') {
    dropCache('scan');
    const nets = await scanWifi(true);
    return json(res, { ok: true, networks: nets, count: nets.length, scanAt: new Date().toISOString() });
  }

  if (p === '/api/live') {
    const [live, iface, conns] = await Promise.all([
      liveStats(),
      cached('iface', 3000, wifiInterface),
      cached('conns', 3000, connections),
    ]);
    return json(res, {
      ok: true,
      rates: live.rates,
      counters: live.counters,
      source: live.source,
      quality: quality.last,
      connected: iface && iface.state === 'connected' ? iface : null,
      connections: conns,
      at: Date.now(),
    });
  }

  if (p === '/api/net') return json(res, { ok: true, net: await cached('net', 5000, netInfo) });

  if (p === '/api/devices') {
    const sweep = qs.get('sweep') === '1';
    const d = sweep ? await arpSweep() : await devices();
    if (d.error) return json(res, { ok: false, ...d }, 403);
    return json(res, { ok: true, ...d });
  }

  if (p === '/api/dns') {
    const domain = safeHost(qs.get('domain') || 'google.com');
    if (!domain) return json(res, { ok: false, error: 'invalid domain' }, 400);
    const server = qs.get('server') || null;
    return json(res, { ok: true, ...(await dnsLookup(domain, server)) });
  }

  if (p === '/api/route') {
    const host = safeHost(qs.get('host') || 'google.com');
    if (!host) return json(res, { ok: false, error: 'invalid host' }, 400);
    const hops = Math.min(30, Number(qs.get('hops')) || 12);
    return json(res, { ok: true, ...(await traceRoute(host, hops)) });
  }

  if (p === '/api/speedtest') return json(res, { ok: true, ...(await speedTest()) });
  if (p === '/api/location') return json(res, await cached('loc', 10 * 60 * 1000, () => auditApi.locate()));
  if (p === '/api/audit') return json(res, await auditApi.auditAll());

  if (p === '/api/quality') return json(res, { ok: true, ...(quality.last || {}) });

  if (p === '/api/portscan') {
    const host = safeHost(qs.get('host'));
    if (!host) return json(res, { ok: false, error: 'invalid host' }, 400);
    const ports = (qs.get('ports') || '').split(',').map((s) => parseInt(s, 10)).filter((n) => n > 0 && n < 65536);
    const r = await portScan(host, ports);
    if (r.error) return json(res, { ok: false, ...r }, 403);
    return json(res, { ok: true, ...r });
  }

  if (p === '/api/report') {
    if (req.method !== 'POST') return json(res, { ok: false, error: 'POST required' }, 405);
    const chunks = [];
    let size = 0;
    req.on('data', (c) => { size += c.length; if (size < 4 * 1024 * 1024) chunks.push(c); });
    req.on('end', () => {
      try {
        fs.mkdirSync(REPORTS, { recursive: true });
        const stamp = new Date().toISOString().replace(/[:.]/g, '-');
        const file = path.join(REPORTS, `netrecon-report-${stamp}.txt`);
        const payload = Buffer.concat(chunks).toString('utf8');
        const banner = [
          '============================================================',
          ' NETRECON v2.1 — SECURITY & NETWORK RECONNAISSANCE REPORT',
          '============================================================',
          ' Generated : ' + new Date().toString(),
          ' Host      : ' + os.hostname() + '  (' + os.type() + ' ' + os.release() + ')',
          ' Operator  : ' + os.userInfo().username,
          ' Scope     : local interface + private LAN',
          '------------------------------------------------------------',
          '',
        ].join('\n');
        fs.writeFileSync(file, banner + payload, 'utf8');
        json(res, { ok: true, file, name: path.basename(file), bytes: Buffer.byteLength(payload) });
      } catch (e) {
        json(res, { ok: false, error: String(e.message || e) }, 500);
      }
    });
    return;
  }

  // static (explicit allowlist — never serve source, reports or config)
  const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.ico': 'image/x-icon' };
  if (req.method === 'GET' && !p.startsWith('/api/')) {
    const STATIC_ALLOW = new Set(['index.html', 'app.js', 'styles.css', 'favicon.ico']);
    let name;
    try { name = decodeURIComponent(p === '/' ? 'index.html' : p.replace(/^\/+/, '')); }
    catch { name = ''; }
    if (STATIC_ALLOW.has(name) && !name.includes('/') && !name.includes('\\')) {
      const file = path.join(ROOT, name);
      if (fs.existsSync(file) && fs.statSync(file).isFile()) {
        return send(res, 200, fs.readFileSync(file), MIME[path.extname(file).toLowerCase()] || 'application/octet-stream');
      }
    }
    return json(res, { ok: false, error: 'not found' }, 404);
  }
  return json(res, { ok: false, error: 'not found' }, 404);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);
  api(req, res, url).catch((e) => {
    const msg = String(e && e.stack || e);
    console.error('\x1b[31m[!]\x1b[0m ' + req.method + ' ' + url.pathname + ' -> ' + msg.split('\n')[0]);
    json(res, { ok: false, error: String(e && e.message || e) }, 500);
  });
});

process.on('unhandledRejection', (e) => {
  console.error('\x1b[31m[!]\x1b[0m unhandled rejection: ' + String(e && e.stack || e).split('\n')[0]);
});

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`\n[!] port ${PORT} is already in use. Set a different port:  set PORT=8788 && node server.js\n`);
  } else console.error('[!]', e.message);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  const line = '='.repeat(62);
  console.log(`\x1b[36m${line}\x1b[0m`);
  console.log('  \x1b[1m\x1b[36mNETRECON v2.1\x1b[0m  \x1b[2m// local reconnaissance backend\x1b[0m');
  console.log(`\x1b[36m${line}\x1b[0m`);
  console.log(`  \x1b[32m[+]\x1b[0m listening   \x1b[36mhttp://${HOST}:${PORT}\x1b[0m`);
  console.log(`  \x1b[32m[+]\x1b[0m bind scope  \x1b[33mloopback only\x1b[0m`);
  console.log(`  \x1b[32m[+]\x1b[0m platform    ${os.type()} ${os.release()}`);
  console.log(`  \x1b[32m[+]\x1b[0m reports ->  \x1b[2m${REPORTS}\x1b[0m`);
  console.log(`\x1b[36m${line}\x1b[0m`);
  console.log('  Open the dashboard:  \x1b[36mhttp://' + HOST + ':' + PORT + '/\x1b[0m');
  console.log('  Stop the server   :  \x1b[33mCtrl+C\x1b[0m\n');
});
