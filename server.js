require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: [
    'https://oskarikaile.github.io',
    /^http:\/\/localhost(:\d+)?$/,
  ],
}));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'docs')));

// --- Simple in-memory stats + cache ---
const stats = {
  ipsChecked: 0,
  threatsFoundToday: 0,
  cvesThisWeek: 0,
  startedAt: new Date().toISOString(),
};

const cache = new Map();
function getCache(key, ttlMs) {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.t < ttlMs) return hit.v;
  return null;
}
function setCache(key, v) {
  cache.set(key, { v, t: Date.now() });
}

// --- IP Lookup (AbuseIPDB) ---
app.get('/api/ip/:ip', async (req, res) => {
  const ip = req.params.ip;
  if (!/^[0-9a-fA-F:.]+$/.test(ip)) return res.status(400).json({ error: 'Invalid IP' });

  stats.ipsChecked++;
  const cached = getCache('ip:' + ip, 5 * 60 * 1000);
  if (cached) return res.json(cached);

  try {
    if (!process.env.ABUSEIPDB_KEY) {
      const mock = mockIpLookup(ip);
      if (mock.abuseConfidenceScore > 25) stats.threatsFoundToday++;
      setCache('ip:' + ip, mock);
      return res.json(mock);
    }

    const r = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`,
      { headers: { Key: process.env.ABUSEIPDB_KEY, Accept: 'application/json' } }
    );
    const j = await r.json();
    const d = j.data || {};
    const result = {
      ip: d.ipAddress || ip,
      abuseConfidenceScore: d.abuseConfidenceScore ?? 0,
      countryCode: d.countryCode || 'XX',
      countryName: d.countryName || 'Unknown',
      isp: d.isp || 'Unknown',
      domain: d.domain || '',
      usageType: d.usageType || '',
      totalReports: d.totalReports ?? 0,
      lastReportedAt: d.lastReportedAt || null,
      categories: extractCategories(d.reports || []),
      isPublic: d.isPublic,
      isTor: d.isTor,
    };
    if (result.abuseConfidenceScore > 25) stats.threatsFoundToday++;
    setCache('ip:' + ip, result);
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

const CATEGORY_MAP = {
  3: 'Fraud Orders', 4: 'DDoS Attack', 5: 'FTP Brute-Force', 6: 'Ping of Death',
  7: 'Phishing', 8: 'Fraud VoIP', 9: 'Open Proxy', 10: 'Web Spam',
  11: 'Email Spam', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
  17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
  21: 'Web App Attack', 22: 'SSH Abuse', 23: 'IoT Targeted',
};
function extractCategories(reports) {
  const set = new Set();
  for (const r of reports.slice(0, 30)) {
    for (const c of r.categories || []) {
      if (CATEGORY_MAP[c]) set.add(CATEGORY_MAP[c]);
    }
  }
  return Array.from(set);
}

function mockIpLookup(ip) {
  const seed = ip.split('.').reduce((a, b) => a + parseInt(b || 0), 0);
  const score = (seed * 13) % 100;
  const countries = [['US','United States'],['RU','Russia'],['CN','China'],['BR','Brazil'],['IN','India'],['DE','Germany'],['NG','Nigeria'],['KP','North Korea']];
  const isps = ['DigitalOcean LLC','Amazon AWS','OVH SAS','China Telecom','Hetzner','Rostelecom','Linode'];
  const cats = ['SSH Abuse','Port Scan','Brute-Force','Web App Attack','SQL Injection','Phishing','DDoS Attack'];
  const [cc, name] = countries[seed % countries.length];
  return {
    ip, abuseConfidenceScore: score, countryCode: cc, countryName: name,
    isp: isps[seed % isps.length], domain: '', usageType: 'Data Center/Web Hosting',
    totalReports: (seed * 7) % 400, lastReportedAt: new Date(Date.now() - 86400000).toISOString(),
    categories: cats.slice(0, (seed % 4) + 1), isPublic: true, isTor: false, _mock: true,
  };
}

// --- CVE Feed (NVD) ---
app.get('/api/cves', async (req, res) => {
  const severity = (req.query.severity || '').toUpperCase();
  const key = 'cves:' + severity;
  const cached = getCache(key, 10 * 60 * 1000);
  if (cached) return res.json(cached);

  try {
    const pub = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, -5);
    const now = new Date().toISOString().slice(0, -5);
    let url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${pub}&pubEndDate=${now}&resultsPerPage=40`;
    if (['CRITICAL','HIGH','MEDIUM','LOW'].includes(severity)) {
      url += `&cvssV3Severity=${severity}`;
    }
    const headers = { Accept: 'application/json' };
    if (process.env.NVD_KEY) headers.apiKey = process.env.NVD_KEY;

    const r = await fetch(url, { headers });
    if (!r.ok) throw new Error('NVD ' + r.status);
    const j = await r.json();
    const out = (j.vulnerabilities || []).map(v => {
      const c = v.cve;
      const m = (c.metrics?.cvssMetricV31?.[0] || c.metrics?.cvssMetricV30?.[0] || c.metrics?.cvssMetricV2?.[0]) || {};
      return {
        id: c.id,
        description: (c.descriptions?.find(d => d.lang === 'en')?.value) || '',
        published: c.published,
        severity: m.cvssData?.baseSeverity || m.baseSeverity || 'UNKNOWN',
        score: m.cvssData?.baseScore ?? null,
        vector: m.cvssData?.vectorString || '',
      };
    });
    stats.cvesThisWeek = j.totalResults ?? out.length;
    setCache(key, out);
    res.json(out);
  } catch (e) {
    const mock = mockCves(severity);
    stats.cvesThisWeek = mock.length;
    res.json(mock);
  }
});

function mockCves(severity) {
  const sevs = severity ? [severity] : ['CRITICAL','HIGH','MEDIUM','LOW'];
  const samples = [
    ['CVE-2026-1042','Remote code execution in widely deployed reverse proxy via crafted Host header.'],
    ['CVE-2026-0998','Heap overflow in libpng image decoder allowing arbitrary code execution.'],
    ['CVE-2026-1187','Authentication bypass in enterprise VPN appliance management interface.'],
    ['CVE-2026-1233','SQL injection in popular CMS plugin allowing database exfiltration.'],
    ['CVE-2026-1311','Use-after-free in Chromium V8 engine triggered by malicious JavaScript.'],
    ['CVE-2026-1402','Path traversal in container runtime allows escape to host filesystem.'],
    ['CVE-2026-1455','XSS in admin panel of network monitoring tool affects 200k installations.'],
    ['CVE-2026-1488','Insecure deserialization in Java-based message broker.'],
  ];
  return samples.map(([id, desc], i) => ({
    id, description: desc,
    published: new Date(Date.now() - i * 86400000).toISOString(),
    severity: sevs[i % sevs.length],
    score: [9.8, 8.4, 7.2, 5.5][i % 4],
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N',
    _mock: true,
  }));
}

// --- Threat feed + map (OTX) ---
app.get('/api/threats', async (req, res) => {
  const cached = getCache('threats', 10 * 60 * 1000);
  if (cached) return res.json(cached);

  try {
    if (!process.env.OTX_KEY) {
      const mock = mockThreats();
      setCache('threats', mock);
      return res.json(mock);
    }
    const r = await fetch('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=30', {
      headers: { 'X-OTX-API-KEY': process.env.OTX_KEY },
    });
    const j = await r.json();
    const pulses = j.results || [];
    const threats = pulses.map(p => ({
      id: p.id,
      name: p.name,
      description: (p.description || '').slice(0, 280),
      author: p.author_name || 'unknown',
      created: p.created,
      tags: p.tags || [],
      malwareFamilies: (p.malware_families || []).map(m => m.display_name || m),
      adversary: p.adversary || '',
      targetedCountries: p.targeted_countries || [],
      industries: p.industries || [],
    }));
    const markers = pulsesToMarkers(pulses);
    const out = { threats, markers };
    setCache('threats', out);
    res.json(out);
  } catch (e) {
    res.json(mockThreats());
  }
});

const COUNTRY_COORDS = {
  'United States':[37.1,-95.7],'Russia':[61.5,105.3],'China':[35.9,104.2],'Brazil':[-14.2,-51.9],
  'India':[20.6,78.96],'Germany':[51.2,10.5],'Nigeria':[9.1,8.7],'North Korea':[40,127],
  'Iran':[32.4,53.7],'Ukraine':[48.4,31.2],'United Kingdom':[55.4,-3.4],'France':[46.2,2.2],
  'South Korea':[35.9,127.8],'Japan':[36.2,138.3],'Israel':[31.0,34.9],'Vietnam':[14.1,108.3],
  'Turkey':[38.96,35.24],'Mexico':[23.6,-102.6],'Indonesia':[-0.8,113.9],
};

function pulsesToMarkers(pulses) {
  const out = [];
  for (const p of pulses) {
    const countries = p.targeted_countries || [];
    for (const c of countries) {
      const coord = COUNTRY_COORDS[c];
      if (!coord) continue;
      out.push({
        lat: coord[0] + (Math.random() - 0.5) * 4,
        lng: coord[1] + (Math.random() - 0.5) * 4,
        name: p.name, country: c, adversary: p.adversary || '',
        malware: (p.malware_families || [])[0]?.display_name || '',
      });
    }
  }
  return out;
}

function mockThreats() {
  const samples = [
    { name: 'Lazarus Group spear-phishing campaign', adversary: 'Lazarus Group', malware: ['BLINDINGCAN'], countries: ['South Korea','United States','Japan'], tags: ['APT','phishing','North Korea'] },
    { name: 'AlphV / BlackCat ransomware targeting healthcare', adversary: 'AlphV', malware: ['BlackCat'], countries: ['United States','Germany','United Kingdom'], tags: ['ransomware','healthcare'] },
    { name: 'TA505 Cl0p exploitation of MOVEit successor', adversary: 'TA505', malware: ['Cl0p'], countries: ['United States','France','Brazil'], tags: ['ransomware','zero-day'] },
    { name: 'Sandworm wiper activity against Ukrainian infra', adversary: 'Sandworm', malware: ['CaddyWiper'], countries: ['Ukraine'], tags: ['wiper','APT','Russia'] },
    { name: 'Mustang Panda PlugX deployment in SE Asia', adversary: 'Mustang Panda', malware: ['PlugX'], countries: ['Vietnam','Indonesia'], tags: ['APT','China'] },
    { name: 'Qakbot revival with new loader chain', adversary: 'TA570', malware: ['Qakbot'], countries: ['United States','Mexico','Brazil'], tags: ['banking-trojan','loader'] },
    { name: 'APT28 credential harvesting via Outlook flaw', adversary: 'APT28', malware: ['HeadLace'], countries: ['Germany','Ukraine','United Kingdom'], tags: ['APT','Russia','credential-access'] },
    { name: 'Charming Kitten social engineering of researchers', adversary: 'Charming Kitten', malware: ['POWERSTAR'], countries: ['Israel','United States'], tags: ['APT','Iran','phishing'] },
  ];
  const threats = samples.map((s, i) => ({
    id: 'mock-' + i,
    name: s.name,
    description: `${s.adversary} observed deploying ${s.malware.join(', ')} against targets in ${s.countries.join(', ')}.`,
    author: 'ThreatScope',
    created: new Date(Date.now() - i * 7200000).toISOString(),
    tags: s.tags, malwareFamilies: s.malware, adversary: s.adversary,
    targetedCountries: s.countries, industries: [],
  }));
  const markers = [];
  for (const s of samples) {
    for (const c of s.countries) {
      const coord = COUNTRY_COORDS[c];
      if (!coord) continue;
      markers.push({
        lat: coord[0] + (Math.random() - 0.5) * 6,
        lng: coord[1] + (Math.random() - 0.5) * 6,
        name: s.name, country: c, adversary: s.adversary, malware: s.malware[0] || '',
      });
    }
  }
  return { threats, markers, _mock: true };
}

// --- Stats ---
app.get('/api/stats', (req, res) => res.json(stats));

app.listen(PORT, () => {
  console.log(`ThreatScope running → http://localhost:${PORT}`);
  if (!process.env.ABUSEIPDB_KEY) console.log('  (using mock IP data — set ABUSEIPDB_KEY in .env for live)');
  if (!process.env.OTX_KEY) console.log('  (using mock OTX threat data — set OTX_KEY in .env for live)');
});
