let allFindings = [];

// --- Scan ---
document.getElementById('scan-btn').addEventListener('click', async () => {
  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  const provider = document.getElementById('provider-select').value;
  const mock = document.getElementById('mock-toggle').checked;

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider, mock }),
    });
    const data = await res.json();
    renderSummary(data);
    allFindings = data.findings || [];
    populateServiceFilter(allFindings);
    renderFindings(allFindings);
  } catch (e) {
    alert('Scan failed: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Scan';
  }
});

// Load findings on page load
(async () => {
  try {
    const res = await fetch('/api/findings');
    const data = await res.json();
    renderSummary(data);
    allFindings = data.findings || [];
    populateServiceFilter(allFindings);
    renderFindings(allFindings);
  } catch {}
})();

function renderSummary(data) {
  document.getElementById('risk-score').textContent = data.risk_score ?? '--';
  document.getElementById('risk-grade').textContent = data.grade ?? '--';
  const b = data.breakdown || {};
  document.getElementById('count-critical').textContent = b.critical || 0;
  document.getElementById('count-high').textContent = b.high || 0;
  document.getElementById('count-medium').textContent = b.medium || 0;
  document.getElementById('count-low').textContent = b.low || 0;
}

function renderFindings(findings) {
  const tbody = document.getElementById('findings-body');
  if (!findings || !findings.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty">No findings.</td></tr>';
    return;
  }
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings = [...findings].sort((a, b) =>
    (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  );

  tbody.innerHTML = findings.map(f => `
    <tr>
      <td><span class="badge badge-${f.severity}">${f.severity}</span></td>
      <td>${f.service || ''}</td>
      <td>${escHtml(f.title)}</td>
      <td><code style="font-size:0.8em;color:var(--muted)">${escHtml((f.resource || '').slice(-60))}</code></td>
      <td><button class="btn-detail" onclick="openDetail(${JSON.stringify(JSON.stringify(f))})">Fix →</button></td>
    </tr>
  `).join('');
}

function populateServiceFilter(findings) {
  const services = [...new Set(findings.map(f => f.service).filter(Boolean))].sort();
  const sel = document.getElementById('service-filter');
  sel.innerHTML = '<option value="">All Services</option>' +
    services.map(s => `<option value="${escHtml(s)}">${escHtml(s)}</option>`).join('');
}

// --- Filters ---
['search-input', 'severity-filter', 'service-filter'].forEach(id => {
  document.getElementById(id).addEventListener('input', applyFilters);
});

function applyFilters() {
  const q = document.getElementById('search-input').value.toLowerCase();
  const sev = document.getElementById('severity-filter').value;
  const svc = document.getElementById('service-filter').value;
  const filtered = allFindings.filter(f => {
    if (sev && f.severity !== sev) return false;
    if (svc && f.service !== svc) return false;
    if (q && !JSON.stringify(f).toLowerCase().includes(q)) return false;
    return true;
  });
  renderFindings(filtered);
}

// --- Modal ---
function openDetail(jsonStr) {
  const f = JSON.parse(jsonStr);
  document.getElementById('modal-title').textContent = f.title;
  document.getElementById('modal-description').textContent = f.description || '';
  document.getElementById('modal-remediation').innerHTML =
    '<p style="color:var(--muted);font-size:0.85em">Ask the AI assistant below for step-by-step remediation, or check the documentation for <strong>' + escHtml(f.service || '') + '</strong>.</p>';
  document.getElementById('modal').classList.remove('hidden');

  // Pre-fill chat with this finding
  document.getElementById('chat-input').value = `How do I fix: ${f.title}?`;
}

document.getElementById('modal-close').addEventListener('click', () => {
  document.getElementById('modal').classList.add('hidden');
});
document.getElementById('modal').addEventListener('click', e => {
  if (e.target === document.getElementById('modal')) {
    document.getElementById('modal').classList.add('hidden');
  }
});

// --- Chat ---
document.getElementById('chat-send').addEventListener('click', sendChat);
document.getElementById('chat-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') sendChat();
});

async function sendChat() {
  const input = document.getElementById('chat-input');
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';
  appendMessage(msg, 'user');

  const thinking = appendMessage('Thinking...', 'bot');
  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg }),
    });
    const data = await res.json();
    thinking.remove();
    let msg = data.answer || 'No answer received.';
    if (data.follow_up_checks && data.follow_up_checks.length) {
      msg += '\n\n**Suggested follow-up checks:**\n' + data.follow_up_checks.map(c => `• ${c}`).join('\n');
    }
    appendMessage(msg, 'bot');
  } catch (e) {
    thinking.remove();
    appendMessage('Error: ' + e.message, 'bot');
  }
}

function appendMessage(text, role) {
  const win = document.getElementById('chat-window');
  const div = document.createElement('div');
  div.className = `message ${role === 'bot' ? 'bot-msg' : 'user-msg'}`;
  div.innerHTML = role === 'bot'
    ? `<strong>CloudGuard AI:</strong> ${escHtml(text)}`
    : `<strong>You:</strong> ${escHtml(text)}`;
  win.appendChild(div);
  win.scrollTop = win.scrollHeight;
  return div;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
