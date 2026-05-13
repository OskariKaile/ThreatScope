// Deployed: point this at your backend host (no trailing slash)
// Locally:  leave empty — requests go to /api/... on the same origin
const API = '';

// ---------- helpers ----------
const $ = sel => document.querySelector(sel);
const flag = cc => cc && cc.length === 2
  ? String.fromCodePoint(...[...cc.toUpperCase()].map(c => 127397 + c.charCodeAt(0)))
  : '🌐';
const fmtRel = d => {
  const s = (Date.now() - new Date(d)) / 1000;
  if (s < 60) return `${s|0}s ago`;
  if (s < 3600) return `${(s/60)|0}m ago`;
  if (s < 86400) return `${(s/3600)|0}h ago`;
  return `${(s/86400)|0}d ago`;
};
const api = path => fetch(API + path).then(r => r.json());

// ---------- Stats bar ----------
async function loadStats() {
  try {
    const s = await api('/api/stats');
    $('#stat-ips').textContent = s.ipsChecked.toLocaleString();
    $('#stat-threats').textContent = s.threatsFoundToday.toLocaleString();
    $('#stat-cves').textContent = s.cvesThisWeek.toLocaleString();
    const up = (Date.now() - new Date(s.startedAt)) / 1000;
    $('#stat-uptime').textContent = up < 3600 ? `${(up/60)|0}m` : `${(up/3600)|0}h`;
  } catch (e) {}
}
setInterval(loadStats, 5000);

// ---------- IP Lookup ----------
$('#ip-form').addEventListener('submit', async e => {
  e.preventDefault();
  const ip = $('#ip-input').value.trim();
  if (!ip) return;
  const box = $('#ip-result');
  box.innerHTML = `<div style="color:var(--muted)">scanning ${ip}…</div>`;
  try {
    const d = await api('/api/ip/' + encodeURIComponent(ip));
    if (d.error) { box.innerHTML = `<div style="color:var(--crit)">${d.error}</div>`; return; }
    const scoreColor = d.abuseConfidenceScore >= 75 ? 'var(--crit)'
      : d.abuseConfidenceScore >= 25 ? 'var(--accent)'
      : 'var(--accent2)';
    box.innerHTML = `
      <div class="score">
        <div class="score-num" style="color:${scoreColor}">${d.abuseConfidenceScore}<span style="font-size:14px;color:var(--muted)">/100</span></div>
        <div class="bar"><div style="width:${d.abuseConfidenceScore}%"></div></div>
      </div>
      <div class="row"><span class="k">IP</span><span style="font-family:monospace">${d.ip}</span></div>
      <div class="row"><span class="k">Country</span><span><span class="flag">${flag(d.countryCode)}</span> ${d.countryName} (${d.countryCode})</span></div>
      <div class="row"><span class="k">ISP</span><span>${d.isp}</span></div>
      <div class="row"><span class="k">Usage</span><span>${d.usageType || '—'}</span></div>
      <div class="row"><span class="k">Reports</span><span>${d.totalReports}</span></div>
      <div class="row"><span class="k">Last reported</span><span>${d.lastReportedAt ? fmtRel(d.lastReportedAt) : '—'}</span></div>
      ${d.categories.length ? `<div class="tags">${d.categories.map(c => `<span class="tag">${c}</span>`).join('')}</div>` : ''}
      ${d._mock ? '<div style="color:var(--muted);font-size:11px;margin-top:8px">⚠ mock data — set ABUSEIPDB_KEY in .env</div>' : ''}
    `;
    loadStats();
  } catch (e) {
    box.innerHTML = `<div style="color:var(--crit)">lookup failed</div>`;
  }
});

// ---------- CVE Feed ----------
let currentSev = '';
async function loadCves() {
  const ul = $('#cve-list');
  ul.innerHTML = `<li style="color:var(--muted)">loading CVE feed…</li>`;
  try {
    const list = await api('/api/cves?severity=' + currentSev);
    if (!list.length) { ul.innerHTML = `<li style="color:var(--muted)">no CVEs found</li>`; return; }
    ul.innerHTML = list.map(c => `
      <li>
        <div class="head">
          <span class="id">${c.id}</span>
          <span class="sev-pill sev-${c.severity}">${c.severity}${c.score ? ' · ' + c.score : ''}</span>
        </div>
        <div class="desc">${(c.description || '').slice(0, 240)}${c.description?.length > 240 ? '…' : ''}</div>
        <div class="meta">published ${fmtRel(c.published)}</div>
      </li>
    `).join('');
    loadStats();
  } catch (e) {
    ul.innerHTML = `<li style="color:var(--crit)">CVE feed failed</li>`;
  }
}
document.querySelectorAll('.sev').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.sev').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentSev = btn.dataset.sev;
    loadCves();
  });
});

// ---------- Threat Feed + Map ----------
const map = L.map('map', { worldCopyJump: true, zoomControl: true })
  .setView([25, 10], 2);

L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
  attribution: '&copy; OpenStreetMap, &copy; CARTO',
  maxZoom: 8, minZoom: 2,
}).addTo(map);

async function loadThreats() {
  try {
    const d = await api('/api/threats');

    (d.markers || []).forEach(m => {
      const icon = L.divIcon({ className: '', html: '<div class="threat-marker"></div>', iconSize: [14,14] });
      L.marker([m.lat, m.lng], { icon }).addTo(map).bindPopup(`
        <div style="font-weight:600;color:var(--accent)">${m.name}</div>
        <div style="font-size:12px;margin-top:4px">
          <div><b>Country:</b> ${m.country}</div>
          ${m.adversary ? `<div><b>Adversary:</b> ${m.adversary}</div>` : ''}
          ${m.malware ? `<div><b>Malware:</b> ${m.malware}</div>` : ''}
        </div>
      `);
    });

    const ul = $('#threat-list');
    ul.innerHTML = (d.threats || []).map(t => `
      <li>
        <div class="name">${t.name}</div>
        ${t.adversary ? `<div class="actor">↳ ${t.adversary}</div>` : ''}
        <div class="desc">${t.description || ''}</div>
        <div class="tags">
          ${(t.malwareFamilies || []).slice(0,3).map(m => `<span class="tag" style="background:rgba(253,122,51,0.12);color:var(--accent);border-color:rgba(253,122,51,0.4)">${m}</span>`).join('')}
          ${(t.targetedCountries || []).slice(0,4).map(c => `<span class="tag">${flag(countryToCC(c))} ${c}</span>`).join('')}
          ${(t.tags || []).slice(0,3).map(x => `<span class="tag">#${x}</span>`).join('')}
        </div>
      </li>
    `).join('');
  } catch (e) {
    $('#threat-list').innerHTML = `<li style="color:var(--crit)">threat feed failed</li>`;
  }
}

function countryToCC(name) {
  const m = {
    'United States':'US','Russia':'RU','China':'CN','Brazil':'BR','India':'IN','Germany':'DE',
    'Nigeria':'NG','North Korea':'KP','Iran':'IR','Ukraine':'UA','United Kingdom':'GB',
    'France':'FR','South Korea':'KR','Japan':'JP','Israel':'IL','Vietnam':'VN','Turkey':'TR',
    'Mexico':'MX','Indonesia':'ID',
  };
  return m[name] || '';
}

// ---------- init ----------
loadStats();
loadCves();
loadThreats();
setInterval(loadCves, 10 * 60 * 1000);
setInterval(loadThreats, 10 * 60 * 1000);
