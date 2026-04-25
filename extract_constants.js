#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const CDP = require('chrome-remote-interface');

function findChrome() {
  if (process.env.CHROME) return process.env.CHROME;
  const candidates = process.platform === 'win32'
    ? [
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
        path.join(os.homedir(), 'AppData/Local/Google/Chrome/Application/chrome.exe'),
      ]
    : process.platform === 'darwin'
    ? [
        '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        '/Applications/Chromium.app/Contents/MacOS/Chromium',
      ]
    : [
        '/usr/bin/google-chrome',
        '/usr/bin/google-chrome-stable',
        '/usr/bin/chromium',
        '/usr/bin/chromium-browser',
      ];
  for (const p of candidates) if (fs.existsSync(p)) return p;
  throw new Error('chrome not found, set CHROME env var');
}

const CHROME = findChrome();
const PROXY = process.env.PROXY || 'http://127.0.0.1:8080';
const TARGET_URL = process.env.TARGET_URL
  || 'https://idp.movistar.com.ar/convergencia/login_A.html';
const CDP_PORT = 9333;
const SID = Buffer.from([0x6c, 0x9b, 0x26, 0xb7]);

function rotl32(v, n) { return ((v << n) | (v >>> (32 - n))) >>> 0; }
function QR(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0; s[d] ^= s[a]; s[d] = rotl32(s[d], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] ^= s[c]; s[b] = rotl32(s[b], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] ^= s[a]; s[d] = rotl32(s[d], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] ^= s[c]; s[b] = rotl32(s[b], 7);
}
const STD_ORDER = [
  [0,4,8,12],[1,5,9,13],[2,6,10,14],[3,7,11,15],
  [0,5,10,15],[1,6,11,12],[2,7,8,13],[3,4,9,14],
];
function chachaBlock(S) {
  const s = S.slice();
  for (let r = 0; r < 8; r++) for (const qr of STD_ORDER) QR(s, ...qr);
  return s.map((v, i) => (v + S[i]) >>> 0);
}

function decipherA(rawCT, sigma, key, counterLO, counterHI) {
  const nonceLO = (rawCT[0]<<24 | rawCT[1]<<16 | rawCT[2]<<8 | rawCT[3]) >>> 0;
  const nonceHI = (rawCT[4]<<24 | rawCT[5]<<16 | rawCT[6]<<8 | rawCT[7]) >>> 0;
  const ct = rawCT.slice(8);
  const pt = Buffer.alloc(ct.length);
  const iters = Math.ceil(ct.length / 64);
  for (let N = 0; N < iters; N++) {
    const S = [
      sigma[0], sigma[1], sigma[2], sigma[3],
      key[0], key[1], key[2], key[3],
      key[4], key[5], key[6], key[7],
      (counterLO + N) >>> 0, counterHI,
      nonceLO, nonceHI,
    ];
    const ks = chachaBlock(S);
    for (let w = 0; w < 16; w++) {
      const off = N*64 + w*4;
      for (let b = 0; b < 4; b++) {
        if (off + b < ct.length) pt[off + b] = ct[off + b] ^ ((ks[w] >>> (8*b)) & 0xff);
      }
    }
  }
  return { plaintext: pt, nonceLO, nonceHI };
}

function decodeCustomB64(s, alpha65) {
  const seen = new Set(s);
  const decoy = [...alpha65].find(c => !seen.has(c));
  const alpha = decoy ? alpha65.replace(decoy, '') : alpha65.slice(0, 64);
  const idx = {};
  for (let i = 0; i < alpha.length; i++) idx[alpha[i]] = i;
  const out = [];
  for (let i = 0; i < s.length; i += 4) {
    const chunk = s.slice(i, i+4);
    const v = [0,0,0,0];
    for (let j = 0; j < chunk.length; j++) v[j] = idx[chunk[j]] | 0;
    out.push(((v[0]<<2) | (v[1]>>4)) & 0xff);
    if (chunk.length >= 3) out.push((((v[1]&0xF)<<4) | (v[2]>>2)) & 0xff);
    if (chunk.length >= 4) out.push((((v[2]&0x3)<<6) | v[3]) & 0xff);
  }
  return Buffer.from(out);
}

function b64urlDecode(s) {
  const pad = (4 - s.length % 4) % 4;
  return Buffer.from(s + '='.repeat(pad), 'base64url');
}

function hashB(s) {
  let h = 0n;
  const M = 0xFFFFFFFFn;
  for (let i = 0; i < s.length; i += 2) {
    const c1 = s.charCodeAt(i);
    const c2 = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
    const pair = BigInt((c1 << 16) | c2);
    h = (h * 31n + pair) & M;
  }
  return Number(h);
}

function base36Signed(s) {
  if (s.startsWith('-')) return -parseInt(s.slice(1), 36);
  return parseInt(s, 36);
}

function bitDump(buf) {
  const bits = [];
  const setIdxs = [];
  for (let i = 0; i < buf.length; i++) {
    bits.push(buf[i].toString(2).padStart(8, '0'));
    for (let b = 0; b < 8; b++) {
      if ((buf[i] >> (7 - b)) & 1) setIdxs.push(i * 8 + b);
    }
  }
  return { binary: bits.join(' '), set_bit_indexes: setIdxs };
}

function decodeF(value) {
  const raw = b64urlDecode(value);
  if (raw.length !== 64) return { length: raw.length, raw_hex: raw.toString('hex') };
  return {
    chars: value.length, bytes: raw.length,
    marker_dep_sig:    raw.slice(0, 8).toString('hex'),
    counter_sequence:  raw.slice(8, 12).toString('hex'),
    per_bundle_nonce:  {
      hex: raw.slice(12, 50).toString('hex'),
      note: 'opaque 38-byte bundle deployment nonce, static per bundle rotation',
    },
    customer_site_id:  {
      hex: raw.slice(50, 64).toString('hex'),
      note: 'invariant for idp.movistar.com.ar',
    },
  };
}

function decodeC(value) {
  const raw = b64urlDecode(value);
  if (raw.length !== 45) return { length: raw.length, raw_hex: raw.toString('hex') };
  return {
    chars: value.length, bytes: raw.length,
    marker:               raw.slice(0, 4).toString('hex'),
    dep_sig:              raw.slice(4, 8).toString('hex'),
    inner_blob: {
      hex: raw.slice(8, 34).toString('hex'),
      note: '26-byte deployment-invariant blob (further encoding not lifted)',
    },
    session_customer_bind: raw.slice(34, 45).toString('hex'),
  };
}

function decodeD(value) {
  const raw = b64urlDecode(value);
  if (raw.length !== 65) return { length: raw.length, raw_hex: raw.toString('hex') };
  const desc = raw.slice(4, 26);
  return {
    chars: value.length, bytes: raw.length,
    marker: raw.slice(0, 4).toString('hex'),
    signal_descriptor: {
      hex: desc.toString('hex'),
      bytes: Array.from(desc),
      ...bitDump(desc),
      note: '22 bytes / 176 bits of probe-ran flags. exact bit-to-probe '
          + 'mapping not fully reversed; deployment-invariant.',
    },
    crypto_mid: {
      hex: raw.slice(26, 38).toString('hex'),
      note: '12 bytes, head 6 deployment-invariant, tail 6 = first half of session bind',
    },
    session_customer_bind: raw.slice(38, 49).toString('hex'),
    trailer_signature: {
      hex: raw.slice(49, 65).toString('hex'),
      note: '16-byte signature, opaque',
    },
  };
}

function decodeB(value, fStr, aStr) {
  const sh = base36Signed(value);
  const uh = sh >>> 0;
  const out = {
    base36: value, signed: sh,
    unsigned: uh, hex: '0x' + uh.toString(16).padStart(8, '0'),
  };
  if (fStr && aStr) {
    const computed = hashB(fStr + aStr);
    out.computed_hex = '0x' + computed.toString(16).padStart(8, '0');
    out.verify = computed === uh ? 'PASS' : 'FAIL';
  }
  return out;
}

const TAG_NAMES = {
  0x07:'tag_07', 0x0e:'net_flag', 0x10:'tag_10', 0x1f:'flag_1f',
  0x26:'key_press', 0x2c:'tag_2c', 0x37:'init_ts', 0x39:'tag_39',
  0x3d:'ua_hash', 0x46:'visibility', 0x47:'tag_47', 0x48:'tag_48',
  0x4a:'battery', 0x4d:'tag_4d', 0x4f:'large_4f', 0x53:'flag_53',
  0x56:'keyboard', 0x59:'timezone', 0x5a:'mouse_batch', 0x5c:'tag_5c',
  0x5f:'tag_5f', 0x67:'tag_67', 0x6a:'flag_6a', 0x6d:'misc_mid',
  0x71:'flag_71', 0x74:'tag_74', 0x78:'tag_78', 0x7b:'focus_blur',
  0x7c:'scroll', 0x84:'tag_84', 0x85:'webgl', 0x86:'canvas_short',
  0x89:'tag_89', 0x8b:'tag_8b', 0x9e:'screen_dims', 0xa0:'init_record',
  0xa3:'kbd_timing', 0xa6:'conn', 0xac:'plugin_count', 0xaf:'dnt_ext',
  0xb3:'flag_b3', 0xb4:'conn_flag', 0xc2:'fp_c2', 0xc4:'tag_c4',
  0xc9:'nav_enum', 0xdd:'tag_dd', 0xe2:'tag_e2', 0xe6:'page_transition',
  0xf5:'tag_f5', 0xf8:'eob', 0xfc:'tag_fc', 0xff:'tag_ff',
};

function parseRecords(b) {
  const positions = [];
  let i = 0;
  while (true) {
    const p = b.indexOf(SID, i);
    if (p < 0) break;
    positions.push(p);
    i = p + 4;
  }
  const records = [];
  for (let k = 0; k < positions.length; k++) {
    const p = positions[k];
    const next = k + 1 < positions.length ? positions[k + 1] : b.length;
    let pick = null;
    for (const w of [1, 2, 3, 4]) {
      if (p < w) continue;
      let L = 0;
      for (let j = p - w; j < p; j++) L = (L << 8) | b[j];
      if (L < 4 || L > 2000) continue;
      const end = p + 4 + (L - 4);
      if (end <= next && end <= b.length) {
        if (!pick || w < pick.w) pick = { w, L, start: p - w, end };
      }
    }
    if (!pick) continue;
    const body = b.slice(p + 4, pick.end);
    records.push({
      offset: pick.start,
      length: pick.L,
      tag: body[0],
      payload: body.slice(1),
    });
  }
  const tagSeen = {};
  return records.map((r, idx) => {
    const base = TAG_NAMES[r.tag] || `tag_${r.tag.toString(16).padStart(2, '0')}`;
    const n = tagSeen[r.tag] || 0;
    tagSeen[r.tag] = n + 1;
    return {
      index: idx,
      offset: r.offset,
      length: r.length,
      tag: '0x' + r.tag.toString(16).padStart(2, '0'),
      name: n === 0 ? base : `${base}_${n}`,
      payload_len: r.payload.length,
      payload_hex: r.payload.toString('hex'),
    };
  });
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

const PREAMBLE = `
(function () {
  var FROZEN_EPOCH_MS = 1776826500000, FROZEN_PERF_MS = 12345;
  var origDate = window.Date;
  function FrozenDate() {
    if (!(this instanceof FrozenDate)) return origDate.apply(null, arguments);
    if (arguments.length === 0) return new origDate(FROZEN_EPOCH_MS);
    if (arguments.length === 1) return new origDate(arguments[0]);
    return new (Function.prototype.bind.apply(origDate, [null].concat([].slice.call(arguments))))();
  }
  FrozenDate.prototype = origDate.prototype;
  FrozenDate.now = function () { return FROZEN_EPOCH_MS; };
  FrozenDate.parse = origDate.parse; FrozenDate.UTC = origDate.UTC;
  try { window.Date = FrozenDate; } catch (e) {}
  Date.now = function () { return FROZEN_EPOCH_MS; };
  if (window.performance) {
    try {
      Object.defineProperty(window.performance, "now", {
        configurable: true, writable: true, value: function () { return FROZEN_PERF_MS; }
      });
    } catch (e) {}
  }
  Math.random = function () { return 0.42424242; };
  if (window.crypto && window.crypto.getRandomValues) {
    window.crypto.getRandomValues = function (arr) {
      if (arr && arr.length != null) {
        var u8 = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
        for (var i = 0; i < u8.length; i++) u8[i] = 0x42;
      }
      return arr;
    };
  }

  window.__probePCs = {};
  window.__probePCs[0x21852] = true;
  window.__probePCs[0x1cf64] = true;
  window.__probeSnaps = [];
  window.__dumpArrLim = 16;

  window.__bootDetail = null;
  var origDispatch = EventTarget.prototype.dispatchEvent;
  EventTarget.prototype.dispatchEvent = function (ev) {
    try {
      if (ev && ev.detail && ev.detail.length >= 4 && typeof ev.detail[1] === 'string' && ev.detail[1].length >= 64) {
        if (!window.__bootDetail) {
          window.__bootDetail = {
            type: ev.type,
            f: ev.detail[0],
            alphabet: ev.detail[1],
            key: Array.isArray(ev.detail[3]) ? ev.detail[3].slice() : null,
          };
        }
      }
    } catch (e) {}
    return origDispatch.apply(this, arguments);
  };

  window.__capturedHeaders = {};
  var origOpen = XMLHttpRequest.prototype.open;
  var origSet = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.open = function (m, u) { this.__url = u; return origOpen.apply(this, arguments); };
  XMLHttpRequest.prototype.setRequestHeader = function (n, v) {
    try {
      if (String(this.__url || '').indexOf('/jct/MovistarEAI/MovistarEAI') >= 0) {
        var key = String(n).toLowerCase();
        if (/^xa4vrhyp3q-[abcdfz]$/.test(key)) {
          window.__capturedHeaders[key] = String(v);
        }
      }
    } catch (e) {}
    return origSet.apply(this, arguments);
  };
})();
`;

const TRIGGER_AND_EXTRACT = `
(function () {
  try {
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/jct/MovistarEAI/MovistarEAI', false);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send('extract');
  } catch (e) {}

  var snaps = window.__probeSnaps || [];
  var iterStart = snaps.find(function (s) { return s.pc === 0x1cf64; });

  function parseInts(str) {
    if (!str || typeof str !== 'string') return null;
    var inner = str.replace(/^\\[|\\]$/g, '').split(',');
    return inner.map(function (x) { return ((+x.trim()) >>> 0); });
  }

  return {
    bootDetail: window.__bootDetail,
    capturedHeaders: window.__capturedHeaders,
    e11_iter0_start: iterStart ? parseInts(iterStart.e_slots[11]) : null,
  };
})();
`;

async function findFreePort(start = CDP_PORT) {
  const net = require('net');
  for (let p = start; p < start + 20; p++) {
    const ok = await new Promise(resolve => {
      const s = net.createServer();
      s.once('error', () => resolve(false));
      s.once('listening', () => s.close(() => resolve(true)));
      s.listen(p, '127.0.0.1');
    });
    if (ok) return p;
  }
  throw new Error('no free port');
}

async function main() {
  const args = process.argv.slice(2);
  const raw = args.includes('--raw');
  const outIdx = args.indexOf('--out');
  const outPath = outIdx >= 0 ? args[outIdx + 1] : null;

  const port = await findFreePort();
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shape-extract-'));

  console.error(`[*] launching headless chrome on :${port}, proxy=${PROXY}`);
  const chrome = spawn(CHROME, [
    `--remote-debugging-port=${port}`,
    `--proxy-server=${PROXY}`,
    '--ignore-certificate-errors',
    '--no-sandbox',
    '--disable-gpu',
    '--headless=new',
    `--user-data-dir=${userDataDir}`,
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'ignore'] });

  let exitCode = 0;
  try {
    let client = null;
    for (let i = 0; i < 30; i++) {
      try { client = await CDP({ port }); break; } catch (e) { await sleep(200); }
    }
    if (!client) throw new Error('CDP did not come up');

    const { Page, Runtime } = client;
    await Page.enable();
    await Runtime.enable();
    await Page.addScriptToEvaluateOnNewDocument({ source: PREAMBLE });

    console.error(`[*] navigating to ${TARGET_URL}`);
    await Page.navigate({ url: TARGET_URL });
    await Page.loadEventFired();
    await sleep(1500);

    console.error(`[*] triggering sensor + extracting state`);
    const { result } = await Runtime.evaluate({
      expression: TRIGGER_AND_EXTRACT,
      returnByValue: true,
    });
    if (result.subtype === 'error') throw new Error('extract failed: ' + JSON.stringify(result));
    const data = result.value;
    if (!data || !data.e11_iter0_start) {
      throw new Error('no probe snaps. is mitmdump running pin_shape.py on :8080?');
    }

    const e11 = data.e11_iter0_start;
    const constants = {
      bundle_seed_f: data.bootDetail && data.bootDetail.f,
      alphabet: data.bootDetail && data.bootDetail.alphabet,
      key: data.bootDetail && data.bootDetail.key,
      sigma: e11.slice(0, 4),
      counter_LO_start: e11[12],
      counter_HI: e11[13],
      sample_nonce_LO: e11[14],
      sample_nonce_HI: e11[15],
    };

    const headers = data.capturedHeaders || {};
    const fields = {};
    for (const k of ['z', 'f', 'c', 'd', 'b', 'a']) {
      const v = headers['xa4vrhyp3q-' + k];
      if (v != null) fields[k] = v;
    }

    const decoded = {};
    if (fields.z) decoded.z = { value: fields.z };
    if (fields.f) decoded.f = decodeF(fields.f);
    if (fields.c) decoded.c = decodeC(fields.c);
    if (fields.d) decoded.d = decodeD(fields.d);
    if (fields.b) decoded.b = decodeB(fields.b, fields.f, fields.a);

    const output = { constants, sensor: { headers: fields, decoded } };

    if (fields.a) {
      const rawCT = decodeCustomB64(fields.a, constants.alphabet);
      const { plaintext, nonceLO, nonceHI } = decipherA(
        rawCT, constants.sigma, constants.key,
        constants.counter_LO_start, constants.counter_HI
      );
      let occ = 0, off = 0;
      while (true) { const j = plaintext.indexOf(SID, off); if (j < 0) break; occ++; off = j + 1; }
      const a = {
        chars: fields.a.length,
        ciphertext_bytes: rawCT.length,
        plaintext_bytes: plaintext.length,
        nonce_LO: '0x' + nonceLO.toString(16).padStart(8, '0'),
        nonce_HI: '0x' + nonceHI.toString(16).padStart(8, '0'),
        session_id_marker_count: occ,
        status: occ >= 5 ? 'PASS' : 'FAIL',
      };
      if (raw) a.plaintext_hex = plaintext.toString('hex');
      else a.records = parseRecords(plaintext);
      decoded.a = a;
      console.error(`[*] decrypted -a: ${plaintext.length} B, ${occ} markers, ${a.records ? a.records.length + ' records' : 'raw hex'}`);
    } else {
      console.error('[!] no -a captured');
    }

    const json = JSON.stringify(output, null, 2);
    if (outPath) {
      fs.writeFileSync(outPath, json);
      console.error(`[*] wrote ${outPath}`);
    }
    process.stdout.write(json + '\n');
    await client.close();
  } catch (e) {
    console.error('[!] ' + e.message);
    exitCode = 1;
  } finally {
    chrome.kill('SIGKILL');
    try { fs.rmSync(userDataDir, { recursive: true, force: true }); } catch (e) {}
  }
  process.exit(exitCode);
}

main();
