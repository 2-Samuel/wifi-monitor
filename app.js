'use strict';
/* ============================================================
   NETRECON v2.1 — dashboard data layer
   Consumes the local backend (server.js). No mock values:
   every figure rendered here comes from the host's network stack.
   ============================================================ */

const $ = (id) => document.getElementById(id);
const setText = (id, v) => { const e = $(id); if (e) e.textContent = v == null || v === '' ? '\u2014' : String(v); };
const setHTML = (id, v) => { const e = $(id); if (e) e.innerHTML = v; };

/* ---------------- formatting helpers ---------------- */
const nz = (n, d = 1) => (n == null || !isFinite(n) ? '\u2014' : Number(n).toFixed(d));
function fmtBytes(b) {
  if (b == null || !isFinite(b)) return '\u2014';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = b;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v.toFixed(0) : v.toFixed(v < 10 ? 2 : 1)) + ' ' + u[i];
}
const fmtInt = (n) => (n == null || !isFinite(n) ? '\u2014' : Math.round(n).toLocaleString());
const hhmmss = (d) => [d.getHours(), d.getMinutes(), d.getSeconds()].map((v) => String(v).padStart(2, '0')).join(':');
function tSince(iso) {
  if (!iso) return '\u2014';
  const d = new Date(iso);
  return isNaN(d) ? '\u2014' : hhmmss(d);
}
function sigClass(dbm) {
  if (dbm == null) return '';
  if (dbm >= -60) return 'on';
  if (dbm >= -75) return 'mid';
  return 'low';
}
function dbmClass(dbm) {
  if (dbm == null) return '';
  if (dbm >= -60) return 'e';
  if (dbm >= -75) return 'g';
  if (dbm >= -88) return 'y';
  return 'w';
}
function sigWord(dbm) {
  if (dbm == null) return '';
  if (dbm >= -50) return 'Excellent';
  if (dbm >= -60) return 'Good';
  if (dbm >= -70) return 'Fair';
  if (dbm >= -80) return 'Weak';
  return 'Poor';
}
function bars(pct) {
  const filled = pct >= 80 ? 4 : pct >= 60 ? 4 : pct >= 45 ? 3 : pct >= 28 ? 2 : 1;
  const cls = pct >= 60 ? 'on' : pct >= 35 ? 'mid' : 'low';
  let out = '<span class="sig ' + cls + '">';
  for (let i = 1; i <= 4; i++) out += '<i class="' + (i <= filled ? 'on' : '') + '"></i>';
  return out + '</span>';
}
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const clip = (s, n) => { s = String(s == null ? '' : s); return s.length > n ? s.slice(0, n - 1) + '\u2026' : s; };
const padCol = (s, n) => { s = String(s == null ? '' : s); return s.length >= n ? s.slice(0, n - 1) + ' ' : s.padEnd(n); };
const secChip = (s) => {
  const k = (s || '').toUpperCase();
  const cls = k.startsWith('WPA3') ? 'wpa3' : k === 'WEP' ? 'wep' : k === 'OPEN' ? 'hidden' : 'wpa2';
  return '<span class="chip ' + cls + '">' + esc(k || '?') + '</span>';
};

/* ---------------- toasts ---------------- */
const toast = (msg) => {
  const t = document.createElement('div');
  t.className = 'toast';
  t.innerHTML = msg;
  $('toast').appendChild(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 320); }, 2600);
};

/* ---------------- api ---------------- */
let apiDown = false;
const API = 'http://127.0.0.1:8787';
async function api(path, opts) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), (opts && opts.timeout) || 30000);
  try {
    const r = await fetch(API + path, { signal: ctl.signal, cache: 'no-store', ...(opts || {}) });
    const j = await r.json();
    if (apiDown) { apiDown = false; $('banner').classList.remove('on'); toast('&gt; backend <b>reconnected</b>'); }
    return j;
  } catch (e) {
    if (!apiDown) { apiDown = true; $('banner').classList.add('on'); }
    return { ok: false, error: String(e.message || e) };
  } finally { clearTimeout(timer); }
}

/* ============================================================
   SIDEBAR
   ============================================================ */
const NAV = [
  { n: '01', t: 'Wi-Fi Discovery', k: 'W', i: 'wifi' },
  { n: '02', t: 'Network Info', k: 'I', i: 'info' },
  { n: '03', t: 'Live Traffic', k: 'T', i: 'graph' },
  { n: '04', t: 'Speed Test', k: 'S', i: 'speed' },
  { n: '05', t: 'Route Analysis', k: 'R', i: 'route' },
  { n: '06', t: 'Connected Devices', k: 'D', i: 'dev' },
  { n: '07', t: 'DNS Analysis', k: 'N', i: 'dns' },
  { n: '08', t: 'Port Scan', k: 'P', i: 'port' },
  { n: '09', t: 'Topology Map', k: 'M', i: 'topo' },
  { n: '10', t: 'Report', k: 'E', i: 'rep' },
  { n: '11', t: 'Geolocation', k: 'G', i: 'geo' },
  { n: '12', t: 'Security Audit', k: 'C', i: 'audit' },
  { n: '--', t: 'Settings', k: ',', i: 'set' },
  { n: 'XX', t: 'Exit', k: 'Q', i: 'exit' },
];
const ICONS = {
  wifi: '<path d="M2 6a11 11 0 0 1 12 0"/><path d="M4.4 9.2a7.4 7.4 0 0 1 7.2 0"/><path d="M6.8 12.2a3.9 3.9 0 0 1 2.4 0"/><circle cx="8" cy="14.2" r="1" fill="currentColor" stroke="none"/>',
  info: '<circle cx="8" cy="8" r="6.4"/><path d="M8 7.2v4.2M8 4.9v.1"/>',
  graph: '<path d="M1.5 13.5h13"/><path d="M2.5 11 6 7l3 2.6L14 3.6"/>',
  speed: '<path d="M2.5 12.5a6 6 0 1 1 11 0"/><path d="M8 12.5 11 7"/><circle cx="8" cy="12.5" r="1.1" fill="currentColor" stroke="none"/>',
  route: '<circle cx="3" cy="3.6" r="1.7"/><circle cx="13" cy="12.4" r="1.7"/><path d="M3 5.3v3.4a3.4 3.4 0 0 0 3.4 3.4h4.9"/>',
  dev: '<rect x="1.5" y="3" width="13" height="8" rx="1"/><path d="M5 14h6M8 11v3"/>',
  dns: '<circle cx="8" cy="8" r="6.4"/><path d="M1.6 8h12.8M8 1.6c2 2.4 2 10.4 0 12.8-2-2.4-2-10.4 0-12.8"/>',
  port: '<rect x="1.5" y="6" width="13" height="8" rx="1"/><path d="M4.5 6V4.2h7V6"/><circle cx="5" cy="10" r="1" fill="currentColor" stroke="none"/>',
  topo: '<circle cx="8" cy="2.8" r="1.7"/><circle cx="3" cy="13" r="1.7"/><circle cx="13" cy="13" r="1.7"/><path d="M8 4.5v3.4M8 7.9 3 11.6M8 7.9l5 3.7"/>',
  rep: '<path d="M3 1.8h6.4L13 5.4v8.8H3z"/><path d="M9.2 1.8v3.8H13M5.4 8.6h5.2M5.4 11h3.4"/>',
  geo: '<circle cx="8" cy="8" r="6.4"/><path d="M1.6 8h12.8M8 1.6c2 2.4 2 10.4 0 12.8-2-2.4-2-10.4 0-12.8"/>',
  audit: '<path d="M8 1.6 14 4v4.4c0 3.4-2.4 5.6-6 6.4-3.6-.8-6-3-6-6.4V4z"/><path d="M5.6 8 7.4 9.8l3.2-3.4"/>',
  set: '<circle cx="8" cy="8" r="2.2"/><path d="M8 1.4v2M8 12.6v2M1.4 8h2M12.6 8h2M3.3 3.3l1.4 1.4M11.3 11.3l1.4 1.4M12.7 3.3l-1.4 1.4M4.7 11.3l-1.4 1.4"/>',
  exit: '<path d="M6 2.6H2.6v10.8H6"/><path d="M9.4 5.6 12.8 8l-3.4 2.4M12.8 8H5.6"/>',
};
$('nav').innerHTML = NAV.map((m, i) => {
  const sep = m.t === 'Settings' ? '<div class="nav-sep"></div>' : '';
  return sep + '<div class="nav-item' + (i === 0 ? ' active' : '') + (m.t === 'Exit' ? ' exit' : '') + '" data-m="' + m.t + '">' +
    '<span class="n">' + m.n + '</span>' +
    '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round">' + ICONS[m.i] + '</svg>' +
    '<span class="tx">' + m.t + '</span><span class="kb">' + m.k + '</span></div>';
}).join('');

const PANEL_OF = {
  'Wi-Fi Discovery': 'scan', 'Network Info': 'net', 'Live Traffic': 'traffic', 'Speed Test': 'speed',
  'Route Analysis': 'route', 'Connected Devices': 'devices', 'DNS Analysis': 'dns', 'Port Scan': 'portscan',
  'Topology Map': 'topo', 'Report': 'report', 'Geolocation': 'geo', 'Security Audit': 'audit',
};
const ACT = {
  scan: () => scanWifi(true),
  net: () => { refreshNet(); refreshDevices(); },
  traffic: () => toast('&gt; capture active on <b>' + (state.net.interface || 'iface') + '</b>'),
  speed: () => runSpeedTest(),
  route: () => runTrace(),
  devices: () => sweepLan(),
  dns: () => runDns($('dnsInput').value),
  portscan: () => portScanDialog(),
  topo: () => sweepLan(),
  report: () => saveReport(),
  geo: () => runLocate(),
  audit: () => runAudit(),
};
$('nav').addEventListener('click', (e) => {
  const it = e.target.closest('.nav-item');
  if (!it) return;
  document.querySelectorAll('.nav-item').forEach((n) => n.classList.remove('active'));
  it.classList.add('active');
  const fn = ACT[PANEL_OF[it.dataset.m]];
  if (fn) fn();
  else toast('&gt; module <b>' + esc(it.dataset.m) + '</b> &mdash; read-only view');
});

/* ============================================================
   STATE
   ============================================================ */
const state = { net: {}, connected: null, devices: [], connections: null, speed: null, geo: null, audit: null, booted: false };
const N = 120;                       // 120 x 500 ms = 60 s
const series = { dn: [], up: [], max: 10 };
const charts = {};

/* ============================================================
   CHARTS
   ============================================================ */
function setupCanvas(id) {
  const el = $(id);
  const c = { el, ctx: el.getContext('2d'), w: 0, h: 0 };
  const resize = () => {
    const r = el.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const h = el.clientHeight || parseInt(el.getAttribute('height'), 10) || 140;
    if (!r.width) return;
    el.width = Math.max(1, Math.floor(r.width * dpr));
    el.height = Math.floor(h * dpr);
    el.style.height = h + 'px';
    c.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    c.w = r.width; c.h = h;
  };
  resize();
  window.addEventListener('resize', resize);
  return c;
}
function drawChart(c, max, unit) {
  const ctx = c.ctx;
  if (!ctx || !c.w) return;
  const w = c.w, h = c.h;
  ctx.clearRect(0, 0, w, h);

  for (let i = 0; i <= 5; i++) {
    const y = Math.round(h - (h / 5) * i) + .5;
    ctx.strokeStyle = i === 5 ? 'rgba(0,229,255,.20)' : 'rgba(18,33,46,.85)';
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
  }
  for (let i = 0; i <= 6; i++) {
    const x = Math.round((w / 6) * i) + .5;
    ctx.strokeStyle = 'rgba(18,33,46,.7)';
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
  }
  ctx.font = '9px "JetBrains Mono",Consolas,monospace';
  ctx.fillStyle = 'rgba(77,114,134,.85)';
  ctx.textAlign = 'right';
  for (let i = 0; i <= 5; i++) {
    const v = (max / 5) * (5 - i);
    ctx.fillText(unit === 'Mbps' ? (max >= 20 ? v.toFixed(0) : v.toFixed(1)) : v.toFixed(1), w - 4, (h - (h / 5) * i) + 3);
  }

  const line = (arr, color, fill) => {
    if (arr.length < 2) return;
    const pts = arr.map((v, i) => [(i / (arr.length - 1)) * w, h - (Math.min(v, max) / max) * (h - 8) - 3]);
    const g = ctx.createLinearGradient(0, 0, 0, h);
    g.addColorStop(0, fill); g.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.beginPath(); ctx.moveTo(0, h);
    pts.forEach((p) => ctx.lineTo(p[0], p[1]));
    ctx.lineTo(w, h); ctx.closePath();
    ctx.fillStyle = g; ctx.fill();

    ctx.beginPath();
    pts.forEach((p, i) => (i ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1])));
    ctx.strokeStyle = color; ctx.lineWidth = 1.5;
    ctx.shadowColor = color; ctx.shadowBlur = 7;
    ctx.stroke(); ctx.shadowBlur = 0;

    const last = pts[pts.length - 1];
    ctx.beginPath(); ctx.arc(last[0] - 1, last[1], 2.6, 0, 7);
    ctx.fillStyle = color; ctx.shadowColor = color; ctx.shadowBlur = 9; ctx.fill();
  };
  line(series.up, 'rgb(176,107,255)', 'rgba(176,107,255,.22)');
  line(series.dn, unit === 'Mbps' ? 'rgb(57,255,158)' : 'rgb(0,229,255)', 'rgba(0,229,255,.20)');
}

/* ============================================================
   RENDERERS
   ============================================================ */
function renderWifi(nets) {
  if (!nets.length) {
    $('wifiBody').innerHTML = '<tr><td colspan="6" class="tbl-fail">no networks reported by the adapter &mdash; press RESCAN</td></tr>';
    return;
  }
  $('wifiBody').innerHTML = nets.map((w, i) => {
    const sel = w.connected;
    const name = w.ssid ? esc(w.ssid) : '<span class="dimtxt">(hidden network)</span>';
    return '<tr class="' + (sel ? 'sel locked' : '') + '">' +
      '<td class="idx num">' + String(i + 1).padStart(2, '0') + '</td>' +
      '<td class="ssid">' + name +
      (w.bssids > 1 ? ' <span class="chip">+' + (w.bssids - 1) + ' bssid</span>' : '') +
      (sel ? '<span class="lock">&#9679; LINKED</span>' : '') + '</td>' +
      '<td class="locked">' + bars(w.signalPct) + '<span class="dbm ' + dbmClass(w.dbm) + ' num">' +
        w.dbm + ' dBm</span> <span class="dimtxt" style="font-size:9.5px">' + w.signalPct + '%</span></td>' +
      '<td class="num locked">' + (w.channel || '\u2014') + '</td>' +
      '<td class="locked">' + secChip(w.security) + '</td>' +
      '<td class="num locked">' + esc(w.frequency || '\u2014') + '</td></tr>';
  }).join('');
}
function renderConnected(c) {
  if (!c) {
    ['cType', 'cSsid', 'cSignal', 'cChan', 'cFreq', 'cSec', 'cRadio'].forEach((k) => setText(k, '\u2014'));
    setHTML('cSignal', '<span class="dimtxt">not associated</span>');
    return;
  }
  setText('cType', 'Wi-Fi');
  setText('cSsid', c.ssid || '(hidden)');
  setHTML('cSignal', '<span class="dbm ' + dbmClass(c.dbm) + ' num">' + c.dbm + ' dBm</span> ' +
    '<span class="' + (c.dbm >= -60 ? 'ok' : 'warn') + '">(' + sigWord(c.dbm) + ')</span>');
  setText('cChan', c.channel || '\u2014');
  setText('cFreq', (c.frequency || '\u2014') + (c.freqMHz ? ' (' + c.freqMHz + ' MHz)' : ''));
  setHTML('cSec', esc(c.security || '\u2014') + (c.cipher ? ' <span class="dimtxt">(' + esc(c.cipher) + ')</span>' : ''));
  setText('cRadio', (c.radioType || '') + ' \u2014 rx ' + nz(c.rxRate) + ' / tx ' + nz(c.txRate) + ' Mbps');
}
function renderNet(n) {
  setText('nIface', n.interface);
  setText('nMac', n.mac);
  setText('nIp', n.ipv4);
  setText('nMask', n.subnet ? n.subnet + ' (/' + n.prefix + ')' : '\u2014');
  setText('nGw', n.gateway || 'none');
  setText('nDns', n.dns && n.dns.length ? n.dns.join(', ') : 'none advertised');
  setText('nDesc', n.description || '\u2014');
  setText('nLink', n.linkSpeed || '\u2014');
  setText('sbIface', n.interface);
  setText('sideIface', 'IF ' + (n.interface || '\u2014'));
  setText('qaScope', 'SCOPE ' + (n.ipv4 ? n.ipv4.split('.').slice(0, 3).join('.') + '.0/' + n.prefix : '\u2014'));
  setText('qaUser', n.interface ? 'local' : '\u2014');
  setText('wIfaceBadge', 'INTERFACE ' + (n.interface || '\u2014'));
  setText('trafficChartTitle', 'Throughput \u2014 ' + (n.interface || 'iface') + ' (last 60 s)');
  setText('topoDev', 'YOUR DEVICE \u2014 ' + (n.interface || ''));
  setText('topoDevSub', (n.ipv4 || '\u2014') + ' \u00b7 ' + (n.mac || '\u2014'));
  setText('topoDevTag', n.interface || '');
  setText('topoRtr', 'ROUTER / GATEWAY');
  setText('topoRtrSub', (n.gateway || 'unreachable') + (state.connected && state.connected.ssid ? ' \u00b7 ' + state.connected.ssid : ''));
  setText('topoLan', 'LAN \u2014 ' + (n.ipv4 ? n.ipv4.split('.').slice(0, 3).join('.') + '.0/' + n.prefix : ''));
  setText('topoGw', n.gateway || '\u2014');
  setText('topoSubnets', n.subnet ? '/' + n.prefix : '\u2014');
}
function renderDevices(d, note) {
  state.devices = d.devices || [];
  if (!state.devices.length) {
    $('devBody').innerHTML = '<tr><td colspan="4" class="tbl-fail">ARP cache empty &mdash; press SWEEP LAN to probe the subnet</td></tr>';
  } else {
    $('devBody').innerHTML = state.devices.map((x) => {
      const role = x.role === 'gateway' ? ' <span class="chip wpa2">GW</span>'
        : x.role === 'self' ? ' <span class="chip wpa3">SELF</span>'
        : x.randomMac ? ' <span class="chip hidden">PRIVATE MAC</span>' : '';
      return '<tr>' +
        '<td class="num" style="color:#cfeaf4">' + esc(x.ip) + '</td>' +
        '<td class="num" style="color:#4d7286">' + esc(x.mac) + '</td>' +
        '<td>' + esc(x.name) + role + '</td>' +
        '<td><span class="dot-online"></span><span class="ok">' + esc(x.status) + '</span></td></tr>';
    }).join('');
  }
  setText('devCount', state.devices.length);
  setText('devScanned', d.scanned ? d.scanned + ' hosts' : 'arp cache');
  setText('devSubnet', 'ARP ' + (d.subnet || '\u2014'));
  setText('devNote', note || '[OK] ' + state.devices.length + ' hosts in ARP cache');
  setText('topoHosts', state.devices.length);
  setText('topoNote', '[OK] ' + state.devices.length + ' hosts mapped');
  const hosts = state.devices.filter((x) => x.role === 'host');
  [1, 2, 3].forEach((i) => {
    const h = hosts[i - 1];
    const id = 'topoD' + i, ids = 'topoD' + i + 's';
    if (h) {
      setText(id, (h.name || 'host').slice(0, 30));
      setText(ids, h.ip + ' \u00b7 ' + h.mac.slice(-8));
    } else {
      setText(id, '\u2014 no host \u2014');
      setText(ids, 'unoccupied');
    }
  });
  if (state.devices.length <= 1) {
    setText('topoNote', '[!] only the gateway answered \u2014 run SWEEP LAN');
  }
}
function renderConnections(c) {
  if (!c) return;
  state.connections = c;
  setText('totConns', c.established + ' est');
  setHTML('totProto', 'TCP <span style="color:var(--cy)">' + c.tcp + '</span> <span style="color:var(--txt-faint)">/</span> UDP <span style="color:var(--pu)">' + c.udp + '</span>');
  setText('countersNote', c.listening + ' listening sockets');
  if (c.topPeers && c.topPeers.length) {
    setText('peerNote', 'TOP REMOTE PEERS  ' + c.topPeers.map((p) => p.ip + (p.n > 1 ? '\u00d7' + p.n : '')).join('   '));
  } else setText('peerNote', 'no remote peers established');
}
function renderTopologyWan(d) {
  const host = (d.hops || []).filter((h) => h.ip).pop();
  setText('topoWanSub', host ? host.ip + ' \u00b7 ' + (host.host || '') .slice(0, 26) : 'uplink not resolved');
  setText('topoWanTag', d.reachedTarget ? 'target reached' : d.reached + ' hops seen');
}
function renderRoute(r) {
  if (!r.ok) {
    $('routeBody').innerHTML = '<tr><td colspan="4" class="tbl-fail err">trace failed: ' + esc(r.error || 'unknown') + '</td></tr>';
    return;
  }
  if (!r.hops.length) {
    $('routeBody').innerHTML = '<tr><td colspan="4" class="tbl-fail">no hops returned</td></tr>';
  } else {
    $('routeBody').innerHTML = r.hops.map((h) => {
      const last = h.ip && h.ip === r.targetIp;
      const cls = !h.ip ? 'hopfail' : h.latency < 10 ? 'gr' : h.latency < 40 ? '' : 'y';
      const col = cls === 'gr' ? '#39ff9e' : cls === 'y' ? '#ffb545' : '#8fbfd0';
      return '<tr class="' + (last ? 'sel' : '') + (h.ip ? '' : ' hopfail') + '">' +
        '<td class="idx num">' + h.hop + '</td>' +
        '<td class="num" style="color:' + (last ? '#eafff4' : 'inherit') + '">' + (h.ip || '*') + '</td>' +
        '<td>' + esc(h.host || '') + '</td>' +
        '<td class="num" style="color:' + (h.latency == null ? 'inherit' : col) + '">' +
          (h.latency == null ? '--' : h.latency + ' ms') + '</td></tr>';
    }).join('');
  }
  setText('rtDest', r.target + (r.targetIp ? ' (' + r.targetIp + ')' : ''));
  setText('rtTotal', r.totalMs + ' ms');
  setText('rtElapsed', (r.elapsed / 1000).toFixed(1) + ' s');
  setText('rtMaxTtl', r.hops.length);
  const note = $('rtNote');
  if (r.reachedTarget) {
    note.className = 'num ok';
    note.textContent = '[+] Route traced successfully \u2014 ' + r.reached + ' hops responded, ' + r.lost + ' filtered';
  } else if (r.filtered) {
    note.className = 'num warn';
    note.textContent = '[!] Intermediate hops filtered ICMP \u2014 only ' + r.reached + ' hop(s) replied. Path reaches ' + esc(r.target) + ' but routers suppress TTL-exceeded replies.';
  } else {
    note.className = 'num warn';
    note.textContent = '[!] Target did not reply within TTL budget \u2014 ' + r.reached + ' hops responded, ' + r.lost + ' timed out.';
  }
}
function renderDns(d) {
  if (!d.ok) {
    setText('dnsDomain', '\u2014');
    setHTML('dnsIp', '<span class="err">lookup failed: ' + esc(d.error || '') + '</span>');
    return;
  }
  setText('dnsDomain', d.domain);
  setHTML('dnsIp', d.records.length
    ? '<span class="ok">' + esc(d.records.join(', ')) + '</span>'
    : '<span class="err">' + esc(d.error || 'no A record') + '</span>');
  setText('dnsTtl', d.ttl == null ? 'not returned by resolver' : d.ttl + ' seconds');
  setText('dnsName', d.domain);
  setText('dnsResolver', d.resolver + ':53 (UDP)');
  setText('dnsQtime', d.queryTime + ' ms');
  setHTML('dnsRecord', 'A &rarr; ' + (d.records.length ? esc(d.records.join(', ')) : '<span class="err">none</span>'));
  setText('dnsPtr', d.ptr ? d.ptr : 'no PTR record');
}

/* ============================================================
   GEOLOCATION + SECURITY AUDIT
   ============================================================ */

/* Coarse equirectangular landmass outlines, [lon, lat]. Decorative
   reference frame only — the marker position is the real datum. */
const WORLD_LAND = {
  'North America': [[-168,65],[-162,71],[-140,70],[-125,70],[-105,69],[-95,70],[-85,70],[-80,63],[-64,60],[-56,52],[-60,47],[-70,42],[-75,36],[-81,25],[-84,30],[-90,29],[-97,26],[-105,22],[-110,23],[-114,31],[-121,35],[-124,40],[-124,48],[-131,55],[-140,60],[-152,59],[-165,55],[-168,65]],
  'Greenland': [[-45,83],[-20,80],[-22,72],[-40,60],[-50,62],[-55,68],[-45,83]],
  'South America': [[-77,8],[-72,12],[-62,11],[-52,5],[-50,0],[-44,-2],[-38,-5],[-35,-8],[-39,-14],[-48,-25],[-53,-34],[-58,-38],[-62,-41],[-65,-45],[-68,-52],[-75,-52],[-73,-45],[-71,-33],[-70,-20],[-75,-15],[-81,-6],[-80,0],[-77,8]],
  'Europe': [[-10,36],[-9,43],[-2,48],[2,51],[4,53],[8,54],[12,55],[10,58],[5,59],[6,63],[12,66],[20,70],[30,70],[40,68],[40,60],[38,55],[30,50],[28,45],[23,42],[20,40],[16,38],[18,40],[12,44],[5,43],[3,42],[-2,36],[-6,36],[-10,36]],
  'Africa': [[-17,15],[-16,21],[-10,26],[-6,32],[0,36],[10,37],[20,32],[32,31],[35,28],[38,22],[43,12],[51,12],[48,5],[41,-2],[40,-10],[35,-19],[33,-26],[28,-33],[20,-35],[18,-33],[14,-23],[12,-16],[9,-1],[5,5],[-5,5],[-8,4],[-13,8],[-17,15]],
  'Asia': [[26,70],[35,68],[45,64],[55,68],[65,70],[75,72],[85,74],[95,76],[105,77],[115,74],[130,73],[142,73],[155,72],[170,69],[180,66],[178,60],[165,60],[155,58],[143,54],[135,48],[130,43],[126,38],[122,31],[120,24],[110,21],[106,10],[103,1],[98,8],[92,22],[88,22],[80,13],[77,8],[70,20],[62,25],[57,25],[48,29],[43,37],[35,36],[30,36],[36,36],[42,38],[50,40],[58,44],[52,48],[44,48],[38,50],[30,46],[26,50],[22,54],[16,58],[13,62],[8,63],[5,60],[8,57],[11,58],[18,60],[22,64],[26,70]],
  'India': [[68,24],[72,20],[73,16],[76,8],[80,10],[80,16],[84,19],[88,21],[92,21],[90,26],[82,29],[74,32],[70,28],[68,24]],
  'SE Asia + Indonesia': [[95,5],[104,2],[106,-6],[114,-8],[120,-9],[126,-8],[130,-6],[141,-3],[141,-8],[135,-5],[130,-3],[125,1],[121,5],[117,4],[110,3],[100,8],[95,5]],
  'Japan': [[130,32],[135,34],[140,36],[142,42],[145,44],[141,45],[138,38],[133,34],[130,32]],
  'Australia': [[114,-22],[113,-26],[116,-32],[120,-34],[129,-32],[137,-35],[141,-38],[147,-38],[150,-35],[153,-28],[146,-19],[142,-11],[136,-12],[130,-11],[126,-14],[121,-19],[114,-22]],
  'New Zealand': [[172,-34],[178,-38],[174,-41],[170,-44],[167,-46],[170,-43],[172,-34]],
};
const MAP_W = 720, MAP_H = 360;
const projX = (lon) => ((lon + 180) / 360) * MAP_W;
const projY = (lat) => ((90 - lat) / 180) * MAP_H;

function drawWorldBase() {
  const grid = $('geoGrid');
  if (!grid) return;
  let g = '';
  for (let lon = -180; lon <= 180; lon += 30) {
    const x = projX(lon).toFixed(1);
    g += '<line class="' + (lon === 0 ? 'maj' : '') + '" x1="' + x + '" y1="0" x2="' + x + '" y2="' + MAP_H + '"/>';
  }
  for (let lat = -90; lat <= 90; lat += 30) {
    const y = projY(lat).toFixed(1);
    g += '<line class="' + (lat === 0 ? 'maj' : '') + '" x1="0" y1="' + y + '" x2="' + MAP_W + '" y2="' + y + '"/>';
  }
  grid.innerHTML = g;
  $('geoLand').innerHTML = Object.values(WORLD_LAND).map((pts) => {
    const d = pts.map((p, i) => (i ? 'L' : 'M') + projX(p[0]).toFixed(1) + ' ' + projY(p[1]).toFixed(1)).join('') + 'Z';
    return '<path d="' + d + '"/>';
  }).join('');
}

function placeGeoMarker(lat, lon) {
  const x = projX(lon), y = projY(lat);
  for (const id of ['geoDot', 'geoRing', 'geoPulse']) {
    const el = $(id);
    if (el) { el.setAttribute('cx', x.toFixed(1)); el.setAttribute('cy', y.toFixed(1)); }
  }
}

async function runLocate() {
  const b = $('geoBtn');
  if (b) b.disabled = true;
  setText('geoNote', 'resolving public IP \u2026');
  const r = await api('/api/location', { timeout: 120000 });
  if (b) b.disabled = false;
  if (!r.ok) {
    setText('geoNote', 'location failed: ' + (r.error || 'unknown') + (r.attempts && r.attempts.length ? ' \u2014 tried ' + r.attempts.join('; ') : ''));
    $('geoNote').className = 'err';
    return;
  }
  state.geo = r;
  placeGeoMarker(r.lat, r.lon);
  setText('geoLatLon', Math.abs(r.lat).toFixed(4) + '\u00b0 ' + (r.lat >= 0 ? 'N' : 'S') + '   ' + Math.abs(r.lon).toFixed(4) + '\u00b0 ' + (r.lon >= 0 ? 'E' : 'W'));
  setText('geoCity', [r.city, r.region].filter(Boolean).join(', ') || '\u2014');
  setText('geoCountry', r.country || '\u2014');
  setText('geoIsp', r.isp || '\u2014');
  setText('geoAs', r.as || '\u2014');
  setText('geoIp', r.ip || '\u2014');
  setText('geoTz', r.timezone ? r.timezone.replace(/_/g, ' ') + (r.tzOffsetMin != null ? ' (UTC' + (r.tzOffsetMin >= 0 ? '+' : '') + r.tzOffsetMin + ')' : '') : '\u2014');
  setText('geoLocal', r.localIp ? r.localIp + (r.gateway ? ' \u2192 ' + r.gateway : '') : '\u2014');
  setText('geoSrc', 'IP-GEOLOCATION');
  setText('geoMethod', r.method || 'ip');
  setText('geoAcc', r.accuracyM ? '\u00b1' + (r.accuracyM >= 1000 ? (r.accuracyM / 1000) + ' km' : r.accuracyM + ' m') : '\u2014');
  setText('geoNote', r.note || '');
  $('geoNote').className = 'dimtxt';
  toast('&gt; located: <b>' + esc([r.city, r.country].filter(Boolean).join(', ')) + '</b>');
}

/* ---------- security audit ---------- */
const SEV_LABEL = { critical: 'CRIT', high: 'HIGH', medium: 'MED', low: 'LOW', ok: 'PASS', info: 'INFO', unknown: 'N/A' };
const SEV_COLOR = { critical: 'var(--rd)', high: 'var(--rd)', medium: 'var(--am)', low: 'var(--cy)', ok: 'var(--gr)', info: 'var(--pu)', unknown: 'var(--pu)' };
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4, info: 5, ok: 6 };
let auditTab = 0;

async function runAudit() {
  const b = $('audBtn');
  if (b) b.disabled = true;
  setText('audVerdict', 'AUDIT RUNNING');
  setText('audHeadline', 'Inspecting host configuration, Wi-Fi link, gateway and this subnet\u2026');
  setText('audDetail', 'Read-only checks. No credential testing, no exploitation.');
  $('audFindings').innerHTML = '<div class="tbl-fail">collecting\u2026</div>';
  const r = await api('/api/audit', { timeout: 400000 });
  if (b) b.disabled = false;
  if (!r.ok) {
    setText('audVerdict', 'AUDIT FAILED');
    setText('audHeadline', r.error || 'unknown error');
    $('audFindings').innerHTML = '<div class="tbl-fail err">' + esc(r.error || 'error') + '</div>';
    return;
  }
  state.audit = r;
  renderAudit(r);
  const v = r.verdict;
  toast('&gt; audit complete \u2014 score <b>' + r.score + '/100</b> (' + r.grade + '), ' + v.weaknesses + ' weak point' + (v.weaknesses === 1 ? '' : 's'));
}

function renderAudit(a) {
  // score gauge
  const CIRC = 2 * Math.PI * 48;
  const arc = $('audArc');
  const col = a.score >= 75 ? 'var(--gr)' : a.score >= 50 ? 'var(--am)' : 'var(--rd)';
  arc.style.stroke = col;
  arc.style.strokeDashoffset = String(CIRC * (1 - a.score / 100));
  $('audScore').textContent = a.score;
  $('audScore').style.color = col;
  setText('audGrade', 'GRADE ' + a.grade);
  $('audGrade').style.color = col;

  const v = a.verdict;
  const vse = $('audVerdict');
  vse.textContent = v.level.toUpperCase();
  vse.style.color = SEV_COLOR[v.sev] || 'var(--am)';
  setText('audHeadline', v.headline);
  setText('audDetail', v.detail);
  $('audHeadline').style.color = v.sev === 'ok' ? 'var(--gr)' : v.sev === 'high' ? 'var(--rd)' : 'var(--am)';

  const s = a.summary;
  $('audCounts').innerHTML = ['critical', 'high', 'medium', 'low', 'ok', 'info', 'unknown']
    .filter((k) => s[k])
    .map((k) => '<span><b style="color:' + (SEV_COLOR[k] || 'var(--dim)') + '">' + s[k] + '</b> ' + k + '</span>').join('');
  setText('audElapsed', (a.elapsed / 1000).toFixed(1) + ' s');

  // tabs
  $('audTabs').innerHTML = a.sections.map((sec, i) => {
    const worst = sec.findings.filter((f) => f.sev !== 'info' && f.sev !== 'ok')
      .reduce((acc, f) => (SEV_RANK[f.sev] < SEV_RANK[acc] ? f.sev : acc), 'ok');
    return '<button class="aud-tab' + (i === auditTab ? ' on' : '') + '" data-i="' + i + '">' +
      esc(sec.title) + '<b class="sev-' + worst + '">' + sec.findings.filter((f) => f.sev !== 'ok' && f.sev !== 'info').length + '</b></button>';
  }).join('');
  $('audTabs').querySelectorAll('.aud-tab').forEach((t) => {
    t.onclick = () => { auditTab = Number(t.dataset.i); renderAudit(a); };
  });

  const sec = a.sections[auditTab] || a.sections[0];
  const sorted = sec.findings.slice().sort((x, y) => SEV_RANK[x.sev] - SEV_RANK[y.sev]);
  let html = '<div class="f-sub">' + esc(sec.subtitle || '') + '</div>';
  html += sorted.map((f, i) =>
    '<div class="finding sev-' + f.sev + '" data-f="' + i + '">' +
    '<div class="f-head"><span class="f-sev">' + (SEV_LABEL[f.sev] || f.sev) + '</span>' +
    '<span class="f-title">' + esc(f.title) + '</span>' +
    '<span class="f-value">' + esc(f.value) + '</span>' +
    '<span class="f-caret">\u25b8</span></div>' +
    '<div class="f-body">' +
    (f.detail ? '<div class="f-detail">' + esc(f.detail) + '</div>' : '') +
    (f.fix ? '<div class="f-fix"><b>FIX</b>' + esc(f.fix) + '</div>' : '') +
    '</div></div>').join('');

  if (sec.id === 'lan' && sec.hits && sec.hits.length) {
    html += '<div class="f-sub" style="margin-top:7px">OPEN SERVICES</div><div class="tbl-wrap"><table><thead><tr>' +
      '<th style="width:120px">HOST</th><th style="width:56px">PORT</th><th style="width:96px">SERVICE</th><th>RISK</th>' +
      '</tr></thead><tbody>' + sec.hits.map((h) =>
        '<tr><td class="mono">' + esc(h.ip) + '</td><td class="mono">' + h.port + '</td><td>' + esc(h.service) +
        ' <span class="dimtxt">' + (h.role === 'self' ? '\u25c9 this host' : h.role === 'gateway' ? '\u25c9 router' : '') + '</span></td>' +
        '<td style="color:' + (SEV_COLOR[h.sev] || 'var(--dim)') + '">' + (SEV_LABEL[h.sev] || h.sev) + '</td></tr>').join('') +
      '</tbody></table></div>';
  }
  $('audFindings').innerHTML = html;
  $('audFindings').querySelectorAll('.finding .f-head').forEach((h) => {
    h.onclick = () => h.parentElement.classList.toggle('open');
  });
  // auto-open the worst finding so the fix is visible without clicking
  const firstBad = $('audFindings').querySelector('.finding.sev-critical, .finding.sev-high, .finding.sev-medium');
  if (firstBad) firstBad.classList.add('open');
}

/* ============================================================
   ACTIONS
   ============================================================ */
async function loadBootstrap() {
  const b = await api('/api/bootstrap', { timeout: 90000 });
  if (!b.ok) return;
  state.booted = true;
  state.net = b.net || {};
  state.connected = b.connected;
  setText('hUser', b.host.user);
  setText('hOs', b.host.platform === 'win32' ? 'Windows' : b.host.os.split(' ')[0]);
  setText('hHost', b.host.hostname);
  setText('mottoVer', 'netrecon v2.1 \u00b7 ' + b.host.hostname);
  setText('sbFound', (b.networks || []).length + ' networks found');
  setText('wFound', (b.networks || []).length);
  setText('wLastScan', tSince(b.scanAt));
  setText('wAdapter', clip(b.connected ? b.connected.description : (b.net.description || ''), 28));
  setText('wBand', b.connected ? (b.connected.band || '\u2014') : '\u2014');
  setText('wRate', b.connected ? nz(b.connected.rxRate) + ' Mbps' : '\u2014');
  setText('wMode', 'netsh wlan show networks');
  setText('wBssids', (b.networks || []).reduce((a, n) => a + (n.bssids || 1), 0));
  setText('wRadio', b.connected ? b.connected.radioType : '\u2014');
  setText('wScanNote', '[OK] scan complete \u2014 ' + (b.networks || []).length + ' APs in range');
  setText('sbScan', '[*] Scanning for Wi-Fi networks... [OK]');
  setText('sbMonitor', 'Monitoring traffic... [OK]');
  renderNet(b.net || {});
  renderConnected(b.connected);
  renderWifi(b.networks || []);
  renderConnections(b.connections);
  if (b.quality) applyQuality(b.quality);
  refreshDevices(false);
}
function applyQuality(q) {
  if (!q) return;
  if (q.latency != null) setText('mPing', q.latency);
  if (q.jitter != null) setText('mJit', nz(q.jitter));
  if (q.loss != null) setText('mLoss', nz(q.loss));
}
async function scanWifi(force) {
  const btn = $('scanBtn');
  btn.disabled = true;
  setText('sbScan', '[*] Rescanning radio...');
  const r = await api('/api/scan', { timeout: 40000 });
  btn.disabled = false;
  if (!r.ok) { toast('&gt; scan failed: <b class="err">' + esc(r.error) + '</b>'); return; }
  renderWifi(r.networks || []);
  setText('wFound', r.count);
  setText('wLastScan', tSince(r.scanAt));
  setText('wScanNote', '[OK] rescan complete \u2014 ' + r.count + ' APs in range');
  setText('sbFound', r.count + ' networks found');
  setText('sbScan', '[*] Scanning for Wi-Fi networks... [OK]');
  toast('&gt; <b>' + r.count + '</b> access points discovered');
}
async function refreshNet() {
  const r = await api('/api/net', { timeout: 40000 });
  if (!r.ok) return;
  state.net = r.net;
  renderNet(r.net);
}
async function refreshDevices(sweep) {
  const r = await api('/api/devices' + (sweep ? '?sweep=1' : ''), { timeout: 180000 });
  if (!r.ok) { setText('devNote', 'scan refused: ' + (r.message || r.error)); return; }
  renderDevices(r, sweep ? '[OK] swept 254 hosts \u2014 ' + (r.devices || []).length + ' live' : null);
  if (sweep) toast('&gt; LAN sweep complete \u2014 <b>' + (r.devices || []).length + '</b> hosts');
}
function sweepLan() {
  const b = $('devSweep');
  b.disabled = true;
  setText('devNote', 'sweeping 254 addresses\u2026');
  setText('sbMonitor', 'Monitoring traffic... [OK] \u00b7 ARP sweep running');
  refreshDevices(true).finally(() => { b.disabled = false; });
}
async function runSpeedTest() {
  const b = $('speedBtn');
  b.disabled = true;
  setText('speedBadge', 'RUNNING');
  setText('sbMonitor', 'Speed test in progress\u2026');
  const r = await api('/api/speedtest', { timeout: 180000 });
  b.disabled = false;
  setText('speedBadge', 'DONE');
  setText('sbMonitor', 'Monitoring traffic... [OK]');
  if (!r.ok) { toast('&gt; speed test failed: <b class="err">' + esc(r.error) + '</b>'); return; }
  state.speed = r;
  setText('mDown', r.download == null ? '--' : nz(r.download, 2));
  setText('mUp', r.upload == null ? '--' : nz(r.upload, 2));
  setText('mPing', r.ping);
  setText('mJit', r.jitter);
  setText('mLoss', r.loss);
  const dScale = Math.max(10, Math.ceil((r.download || 0) * 1.25 / 10) * 10);
  const uScale = Math.max(10, Math.ceil((r.upload || 0) * 1.25 / 10) * 10);
  setText('bDownScale', dScale);
  setText('bUpScale', uScale);
  setText('bDownPct', Math.round(((r.download || 0) / dScale) * 100));
  setText('bUpPct', Math.round(((r.upload || 0) / uScale) * 100));
  $('barDown').style.width = Math.min(100, ((r.download || 0) / dScale) * 100).toFixed(1) + '%';
  $('barUp').style.width = Math.min(100, ((r.upload || 0) / uScale) * 100).toFixed(1) + '%';
  const bits = [];
  bits.push('measured in ' + (r.duration / 1000).toFixed(1) + ' s');
  if (r.downloadBytes) bits.push(fmtBytes(r.downloadBytes) + ' down');
  if (r.uploadBytes) bits.push(fmtBytes(r.uploadBytes) + ' up');
  if (r.pingTarget) bits.push('latency to ' + r.pingTarget);
  setText('speedNote', bits.join(' \u00b7 '));
  if (r.note) { setText('speedNote', bits.join(' \u00b7 ') + ' \u2014 ' + r.note); $('speedNote').className = 'warn'; }
  else $('speedNote').className = 'dimtxt';
  setText('sbDown', r.download == null ? '--' : nz(r.download, 2));
  setText('sbUp', r.upload == null ? '--' : nz(r.upload, 2));
  toast('&gt; speed test complete \u2014 <b>' + nz(r.download, 2) + '</b> / ' + nz(r.upload, 2) + ' Mbps');
}
async function runTrace() {
  const host = ($('rtHost').value || '').trim() || 'google.com';
  const b = $('rtGo');
  b.disabled = true;
  $('routeBody').innerHTML = '<tr><td colspan="4" class="tbl-fail">tracing ' + esc(host) + '\u2026 (up to 12 hops, may take 30 s)</td></tr>';
  const r = await api('/api/route?host=' + encodeURIComponent(host), { timeout: 180000 });
  b.disabled = false;
  renderRoute(r);
  renderTopologyWan(r.ok ? r : {});
  if (r.ok) toast('&gt; route to <b>' + esc(host) + '</b> \u2014 ' + r.reached + ' hops');
}
async function runDns(domain) {
  const d = (domain || '').trim() || 'google.com';
  setText('dnsDomain', d);
  const r = await api('/api/dns?domain=' + encodeURIComponent(d), { timeout: 30000 });
  renderDns(r);
  if (r.ok && r.records.length) toast('&gt; <b>' + esc(d) + '</b> \u2192 ' + esc(r.records[0]));
}
async function portScanDialog() {
  const def = state.net.gateway || state.net.ipv4 || '';
  const host = window.prompt('Port scan target (private/loopback addresses only):', def);
  if (!host) return;
  openModal('PORT SCAN \u2014 ' + esc(host), 'scanning 37 common TCP ports\u2026');
  const r = await api('/api/portscan?host=' + encodeURIComponent(host), { timeout: 120000 });
  if (!r.ok) {
    $('modalBody').innerHTML = '<div class="p-body err">refused: ' + esc(r.message || r.error) + '</div>';
    return;
  }
  const rows = r.open.length
    ? r.open.map((p) => '<tr><td class="num" style="color:#cfeaf4">' + p.port + '</td><td>' + esc(p.service) + '</td>' +
        '<td class="num ok">open</td><td class="num">' + p.latency + ' ms</td>' +
        '<td class="dimtxt">' + esc(p.banner || '\u2014') + '</td></tr>').join('')
    : '<tr><td colspan="5" class="tbl-fail">no open ports among the probed set</td></tr>';
  $('modalBody').innerHTML =
    '<table><thead><tr><th style="width:80px">Port</th><th style="width:130px">Service</th>' +
    '<th style="width:80px">State</th><th style="width:90px">Latency</th><th>Banner</th></tr></thead>' +
    '<tbody>' + rows + '</tbody></table>' +
    '<div class="tbl-foot"><span><b>TARGET</b> <span class="chip">' + esc(r.host) + '</span></span>' +
    '<span><b>PROBED</b> <span class="chip">' + r.scanned + ' ports</span></span>' +
    '<span><b>OPEN</b> <span class="chip wpa2">' + r.openCount + '</span></span>' +
    '<span><b>ELAPSED</b> <span class="chip">' + (r.elapsed / 1000).toFixed(2) + ' s</span></span>' +
    '<span class="ok">TCP connect scan \u2014 no packets sent beyond this subnet</span></div>';
}
function buildReport() {
  const L = [];
  const n = state.net, c = state.connected;
  L.push('--- INTERFACE ---');
  L.push('interface      : ' + (n.interface || '\u2014'));
  L.push('adapter        : ' + (n.description || '\u2014'));
  L.push('mac            : ' + (n.mac || '\u2014'));
  L.push('ipv4           : ' + (n.ipv4 || '\u2014') + '/' + (n.prefix || '\u2014'));
  L.push('subnet mask    : ' + (n.subnet || '\u2014'));
  L.push('gateway        : ' + (n.gateway || '\u2014'));
  L.push('dns            : ' + ((n.dns || []).join(', ') || '\u2014'));
  L.push('link speed     : ' + (n.linkSpeed || '\u2014'));
  L.push('');
  L.push('--- WIRELESS LINK ---');
  L.push('ssid           : ' + (c ? c.ssid : 'not associated'));
  L.push('bssid          : ' + (c ? c.bssid : '\u2014'));
  L.push('signal         : ' + (c ? c.dbm + ' dBm (' + c.signalPct + '%)' : '\u2014'));
  L.push('channel / band : ' + (c ? c.channel + ' / ' + c.band : '\u2014'));
  L.push('rate rx/tx     : ' + (c ? c.rxRate + ' / ' + c.txRate + ' Mbps' : '\u2014'));
  L.push('security       : ' + (c ? c.security + ' (' + c.cipher + ')' : '\u2014'));
  L.push('');
  L.push('--- SPEED TEST ---');
  if (state.speed) {
    const s = state.speed;
    L.push('download       : ' + s.download + ' Mbps (' + fmtBytes(s.downloadBytes) + ' / ' + s.downloadSecs + ' s)');
    L.push('upload         : ' + s.upload + ' Mbps (' + fmtBytes(s.uploadBytes) + ' / ' + s.uploadSecs + ' s)');
    L.push('ping / jitter  : ' + s.ping + ' ms / ' + s.jitter + ' ms');
    L.push('packet loss    : ' + s.loss + ' %');
    L.push('endpoint       : ' + s.server + ' @ ' + s.at);
  } else L.push('not run');
  L.push('');
  L.push('--- CONNECTIONS ---');
  if (state.connections) {
    const k = state.connections;
    L.push('tcp / udp      : ' + k.tcp + ' / ' + k.udp);
    L.push('established    : ' + k.established);
    L.push('listening      : ' + k.listening);
    L.push('top peers      : ' + (k.topPeers || []).map((p) => p.ip).join(', '));
  } else L.push('unavailable');
  L.push('');
  L.push('--- CONNECTED DEVICES (ARP) ---');
  state.devices.forEach((d) => L.push('  ' + padCol(d.ip, 16) + padCol(d.mac, 20) + d.name));
  if (!state.devices.length) L.push('  none');
  L.push('');
  L.push('--- ROUTE ---');
  const rb = $('routeBody').querySelectorAll('tr');
  rb.forEach((tr) => {
    const tds = [...tr.querySelectorAll('td')].map((t) => t.textContent.trim());
    if (tds.length === 4) L.push('  ' + padCol(tds[0], 4) + padCol(tds[1], 18) + padCol(tds[2], 30) + tds[3]);
  });
  L.push('');
  L.push('--- GEOLOCATION ---');
  if (state.geo) {
    L.push('  ' + padCol('coordinates', 16) + Math.abs(state.geo.lat).toFixed(4) + (state.geo.lat >= 0 ? 'N' : 'S') + '  ' + Math.abs(state.geo.lon).toFixed(4) + (state.geo.lon >= 0 ? 'E' : 'W'));
    L.push('  ' + padCol('city / region', 16) + [state.geo.city, state.geo.region].filter(Boolean).join(', '));
    L.push('  ' + padCol('country', 16) + (state.geo.country || ''));
    L.push('  ' + padCol('isp', 16) + (state.geo.isp || ''));
    L.push('  ' + padCol('asn', 16) + (state.geo.as || ''));
    L.push('  ' + padCol('public ip', 16) + (state.geo.ip || ''));
    L.push('  ' + padCol('timezone', 16) + (state.geo.timezone || ''));
    L.push('  ' + padCol('method', 16) + (state.geo.method || '') + '  (accuracy +/-' + (state.geo.accuracyM || '?') + ' m)');
  } else L.push('  not resolved');

  L.push('');
  L.push('--- SECURITY AUDIT ---');
  if (state.audit) {
    const a = state.audit;
    L.push('  ' + padCol('score', 16) + a.score + '/100 (grade ' + a.grade + ')');
    L.push('  ' + padCol('verdict', 16) + a.verdict.level + ' - ' + a.verdict.headline);
    L.push('  ' + padCol('detail', 16) + a.verdict.detail);
    L.push('  ' + padCol('scope', 16) + a.scope);
    L.push('');
    for (const sec of a.sections) {
      L.push('  [' + sec.title + '] ' + sec.subtitle);
      const sorted = sec.findings.slice().sort((x, y) => SEV_RANK[x.sev] - SEV_RANK[y.sev]);
      for (const f of sorted) {
        if (f.sev === 'info' && !f.value) continue;
        L.push('    ' + padCol(SEV_LABEL[f.sev] || f.sev, 6) + padCol(f.title, 44) + f.value);
        if (f.fix) L.push('           fix: ' + f.fix);
      }
      if (sec.id === 'lan' && sec.hits && sec.hits.length) {
        L.push('    open services:');
        for (const h of sec.hits) L.push('      ' + padCol(h.ip, 18) + padCol(String(h.port), 7) + padCol(h.service, 14) + (SEV_LABEL[h.sev] || h.sev));
      }
      L.push('');
    }
  } else L.push('  not run');

  L.push('');
  L.push('NOTE: all values captured from this host\'s network stack.');
  L.push('Audit is a read-only configuration review: it tests no credentials');
  L.push('and performs no exploitation. Probing stayed on this subnet.');
  return L.join('\n');
}

async function saveReport() {
  const body = buildReport();
  const r = await api('/api/report', { method: 'POST', body, timeout: 30000, headers: { 'Content-Type': 'text/plain' } });
  if (!r.ok) { toast('&gt; report failed: <b class="err">' + esc(r.error) + '</b>'); return; }
  toast('&gt; report saved &rarr; <b>' + esc(r.name) + '</b>');
  openModal('REPORT SAVED', '<div class="p-body"><div class="ok">wrote ' + fmtBytes(r.bytes) + ' to</div>' +
    '<div style="margin-top:6px;color:#cfeef8">' + esc(r.file) + '</div></div>');
}
function openModal(title, html) {
  $('modalTitle').textContent = title;
  $('modalBody').innerHTML = typeof html === 'string' && html.startsWith('<')
    ? html : '<div class="p-body">' + esc(html) + '</div>';
  $('modal').classList.add('on');
}
$('modalClose').onclick = () => $('modal').classList.remove('on');
$('modal').addEventListener('click', (e) => { if (e.target === $('modal')) $('modal').classList.remove('on'); });
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') $('modal').classList.remove('on');
  const map = { F1: 'scan', F2: 'devices', F3: 'route', F4: 'dns', F5: 'portscan', F6: 'report' };
  if (map[e.key]) { e.preventDefault(); ACT[map[e.key]](); }
});

/* ---- quick actions ---- */
const QA = [
  ['1', 'Scan Wi-Fi Networks', 'F1', () => scanWifi(true)],
  ['2', 'View Connected Devices', 'F2', () => sweepLan()],
  ['3', 'Trace Route to Host', 'F3', () => runTrace()],
  ['4', 'DNS Lookup', 'F4', () => runDns($('dnsInput').value)],
  ['5', 'Port Scan (Authorized)', 'F5', () => portScanDialog()],
  ['6', 'Save Report', 'F6', () => saveReport()],
];
$('qa').innerHTML = QA.map((a) =>
  '<button data-i="' + a[0] + '"><span class="idx">[' + a[0] + ']</span>' +
  '<span class="lb">' + a[1] + '</span><span class="fk">' + a[2] + '</span></button>').join('');
$('qa').addEventListener('click', (e) => {
  const b = e.target.closest('button');
  if (!b) return;
  const a = QA.find((x) => x[0] === b.dataset.i);
  if (a) a[3]();
});
$('scanBtn').onclick = () => scanWifi(true);
$('speedBtn').onclick = () => runSpeedTest();
$('rtGo').onclick = () => runTrace();
$('rtHost').addEventListener('keydown', (e) => { if (e.key === 'Enter') runTrace(); });
$('dnsGo').onclick = () => runDns($('dnsInput').value);
$('dnsInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') runDns($('dnsInput').value); });
$('devSweep').onclick = () => sweepLan();
$('topoRefresh').onclick = () => { refreshDevices(false); refreshNet(); toast('&gt; topology refreshed'); };

/* ============================================================
   CLOCK + LIVE POLL
   ============================================================ */
setInterval(() => { $('clock').textContent = hhmmss(new Date()); }, 1000);
$('clock').textContent = hhmmss(new Date());

charts.speed = setupCanvas('chartSpeed');
charts.traffic = setupCanvas('chartTraffic');

let lastPoll = 0;
async function poll() {
  const r = await api('/api/live', { timeout: 15000 });
  if (!r.ok) return;
  const now = performance.now();
  const dt = lastPoll ? (now - lastPoll) / 1000 : 0;
  lastPoll = now;

  const bps = r.rates || {};
  const downMbps = (bps.rxBps || 0) * 8 / 1e6;
  const upMbps = (bps.txBps || 0) * 8 / 1e6;
  const downMBs = (bps.rxBps || 0) / 1048576;
  const upMBs = (bps.txBps || 0) / 1048576;

  setText('tDown', nz(downMBs, 2));
  setText('tUp', nz(upMBs, 2));
  setText('tRx', fmtInt(bps.rxPps));
  setText('tTx', fmtInt(bps.txPps));
  setText('sbRx', fmtInt(bps.rxPps) + '/s');
  setText('sbTx', fmtInt(bps.txPps) + '/s');
  setText('trafficSrc', r.source || 'netstat -e');

  if (r.counters) {
    setText('totRx', fmtBytes(r.counters.rxBytes));
    setText('totTx', fmtBytes(r.counters.txBytes));
  }
  renderConnections(r.connections);
  if (r.quality) applyQuality(r.quality);
  if (r.connected) { state.connected = r.connected; renderConnected(r.connected); renderNet(state.net); }

  series.dn.push(downMbps);
  series.up.push(upMbps);
  while (series.dn.length > N) series.dn.shift();
  while (series.up.length > N) series.up.shift();
  const peak = Math.max(1, ...series.dn, ...series.up);
  series.max = Math.max(1, Math.ceil(peak * 1.15 * 10) / 10);
  setText('sMaxLab', '-' + (series.dn.length / 2).toFixed(0) + 's');
  drawChart(charts.speed, series.max, 'Mbps');
  drawChart(charts.traffic, series.max, 'Mbps');
  if (!state.speed) {
    setText('sbDown', nz(downMbps, 2));
    setText('sbUp', nz(upMbps, 2));
  }
  setText('sbScan', '[*] Scanning for Wi-Fi networks... [OK]');
}

(async function init() {
  drawWorldBase();
  $('geoBtn').onclick = runLocate;
  $('audBtn').onclick = runAudit;
  await loadBootstrap();
  poll();
  setInterval(poll, 1000);
  setTimeout(() => { if (state.booted) runDns('google.com'); }, 1500);
  setTimeout(() => { if (state.booted) runTrace(); }, 3000);
  setTimeout(() => { if (state.booted && !state.speed) runSpeedTest(); }, 6000);
  setTimeout(() => { if (state.booted) runLocate(); }, 9000);
  setTimeout(() => { if (state.booted && !state.audit) runAudit(); }, 14000);
})();
