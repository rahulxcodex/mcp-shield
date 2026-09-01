export function getDashboardHtml(token: string, port: number): string {
  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP-Shield Security Command Center</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/lucide@latest"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
    body { font-family: 'Inter', sans-serif; }
    code, pre, .mono { font-family: 'JetBrains Mono', monospace; }
    .threat-pulse { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .5; } }
  </style>
</head>
<body class="bg-[#090a0f] text-slate-100 min-h-screen flex flex-col">
  <!-- Top Navigation Header -->
  <header class="border-b border-slate-800 bg-[#0d0e15]/80 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="h-9 w-9 rounded-xl bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-emerald-500/20">
          <i data-lucide="shield-check" class="w-5 h-5 text-black"></i>
        </div>
        <div>
          <div class="font-bold text-lg leading-tight flex items-center gap-2">
            <span>MCP-SHIELD</span>
            <span class="text-xs bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded-full font-mono font-medium">LIVE PROXY</span>
          </div>
          <div class="text-xs text-slate-400">Zero-Trust AI Agent Security Gateway</div>
        </div>
      </div>
      
      <div class="flex items-center gap-4">
        <div class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300">
          <span id="ws-indicator" class="h-2.5 w-2.5 rounded-full bg-emerald-500 threat-pulse"></span>
          <span id="ws-status">Connected (Port ${port})</span>
        </div>
        <a href="https://github.com/rahulxcodex/mcp-shield" target="_blank" class="text-slate-400 hover:text-white transition">
          <i data-lucide="github" class="w-5 h-5"></i>
        </a>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="max-w-7xl mx-auto px-4 py-6 flex-1 w-full space-y-6">
    <!-- Top KPI Grid -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      <!-- Security Score -->
      <div class="bg-[#0f111a] border border-slate-800/80 rounded-xl p-4 relative overflow-hidden">
        <div class="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Security Health Score</div>
        <div class="flex items-baseline gap-2">
          <span id="stat-score" class="text-3xl font-extrabold text-emerald-400">98</span>
          <span class="text-xs text-slate-500 font-mono">/ 100</span>
        </div>
        <div class="mt-2 text-xs text-emerald-400/80 flex items-center gap-1">
          <i data-lucide="shield" class="w-3.5 h-3.5"></i> Zero-Trust Firewall Enforced
        </div>
      </div>

      <!-- Attacks Blocked -->
      <div class="bg-[#0f111a] border border-slate-800/80 rounded-xl p-4 relative overflow-hidden">
        <div class="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Attacks Neutralized</div>
        <div class="flex items-baseline gap-2">
          <span id="stat-blocked" class="text-3xl font-extrabold text-rose-400">0</span>
          <span class="text-xs text-rose-500 font-mono">threats blocked</span>
        </div>
        <div class="mt-2 text-xs text-slate-400 flex items-center gap-1">
          <i data-lucide="ban" class="w-3.5 h-3.5 text-rose-400"></i> AST, SSRF, & Shell Evasions
        </div>
      </div>

      <!-- Secrets Guarded -->
      <div class="bg-[#0f111a] border border-slate-800/80 rounded-xl p-4 relative overflow-hidden">
        <div class="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Secrets Tokenized (DLP)</div>
        <div class="flex items-baseline gap-2">
          <span id="stat-sanitized" class="text-3xl font-extrabold text-cyan-400">0</span>
          <span class="text-xs text-cyan-500 font-mono">keys redacted</span>
        </div>
        <div class="mt-2 text-xs text-slate-400 flex items-center gap-1">
          <i data-lucide="key" class="w-3.5 h-3.5 text-cyan-400"></i> Zero-Plaintext Storage
        </div>
      </div>

      <!-- Total Interceptions -->
      <div class="bg-[#0f111a] border border-slate-800/80 rounded-xl p-4 relative overflow-hidden">
        <div class="text-xs font-medium text-slate-400 uppercase tracking-wider mb-1">Evaluated Invocations</div>
        <div class="flex items-baseline gap-2">
          <span id="stat-total" class="text-3xl font-extrabold text-indigo-400">0</span>
          <span class="text-xs text-indigo-500 font-mono">hot-path calls</span>
        </div>
        <div class="mt-2 text-xs text-slate-400 flex items-center gap-1">
          <i data-lucide="zap" class="w-3.5 h-3.5 text-indigo-400"></i> <span id="stat-latency">&lt; 0.2 ms</span> mean latency
        </div>
      </div>
    </div>

    <!-- Live Threat Stream & Policy Center -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <!-- Live Real-Time Feed (2 Cols) -->
      <div class="lg:col-span-2 bg-[#0f111a] border border-slate-800 rounded-xl flex flex-col h-[560px]">
        <div class="px-4 py-3 border-b border-slate-800 flex items-center justify-between bg-[#131522]/50 rounded-t-xl">
          <div class="flex items-center gap-2">
            <i data-lucide="activity" class="w-4 h-4 text-emerald-400"></i>
            <span class="font-semibold text-sm">Live Intercept Stream</span>
            <span id="event-badge" class="bg-slate-800 text-slate-300 text-xs px-2 py-0.5 rounded-full font-mono">0 events</span>
          </div>
          <button id="clear-btn" class="text-xs text-slate-400 hover:text-white px-2 py-1 bg-slate-900 border border-slate-800 rounded transition">
            Clear Feed
          </button>
        </div>

        <div id="events-container" class="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs">
          <div id="empty-state" class="h-full flex flex-col items-center justify-center text-slate-500 space-y-2">
            <i data-lucide="radio" class="w-8 h-8 text-slate-600 animate-pulse"></i>
            <p>Listening for agent MCP tool calls...</p>
            <p class="text-[11px] text-slate-600">Run an MCP tool via Claude Desktop, Cursor, or CLI.</p>
          </div>
        </div>
      </div>

      <!-- Quick Policy Switchboard & Honeypot Status (1 Col) -->
      <div class="space-y-6">
        <!-- Active Guardrails -->
        <div class="bg-[#0f111a] border border-slate-800 rounded-xl p-4 space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <div class="font-semibold text-sm flex items-center gap-2">
              <i data-lucide="sliders" class="w-4 h-4 text-cyan-400"></i> Active Gateway Guardrails
            </div>
            <span class="text-xs text-emerald-400 font-mono">ACTIVE</span>
          </div>

          <div class="space-y-2.5 text-xs">
            <div class="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/60">
              <span class="text-slate-300">AST Root Deletion Block</span>
              <span class="text-emerald-400 font-semibold font-mono">ENFORCED</span>
            </div>
            <div class="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/60">
              <span class="text-slate-300">SSRF & Cloud Metadata Guard</span>
              <span class="text-emerald-400 font-semibold font-mono">ENFORCED</span>
            </div>
            <div class="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/60">
              <span class="text-slate-300">DLP Secret Tokenizer</span>
              <span class="text-cyan-400 font-semibold font-mono">BIJECTIVE</span>
            </div>
            <div class="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/60">
              <span class="text-slate-300">Rate Ceiling Throttler</span>
              <span class="text-indigo-400 font-semibold font-mono">15 calls/min</span>
            </div>
          </div>
        </div>

        <!-- Honeytoken Canary Status -->
        <div class="bg-[#0f111a] border border-slate-800 rounded-xl p-4 space-y-3">
          <div class="font-semibold text-sm flex items-center gap-2 border-b border-slate-800/80 pb-3">
            <i data-lucide="sparkles" class="w-4 h-4 text-amber-400"></i> Decoy Honey-Token Tripwire
          </div>
          <p class="text-xs text-slate-400">
            Active decoy canary tokens deployed in LLM context. Any exfiltration attempt triggers immediate session quarantine.
          </p>
          <div class="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300 font-mono flex items-center justify-between">
            <span>mcp_honey_decoy_***</span>
            <span class="text-[10px] bg-amber-500/20 px-1.5 py-0.5 rounded font-bold">ARMED</span>
          </div>
        </div>
      </div>
    </div>
  </main>

  <script>
    lucide.createIcons();
    const token = "${token}";
    const wsProtocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
    const wsUrl = wsProtocol + window.location.host + '/?token=' + token;
    let ws;
    let eventCount = 0;
    let blockedCount = 0;
    let sanitizedCount = 0;

    const eventsContainer = document.getElementById('events-container');
    const emptyState = document.getElementById('empty-state');
    const statTotal = document.getElementById('stat-total');
    const statBlocked = document.getElementById('stat-blocked');
    const statSanitized = document.getElementById('stat-sanitized');
    const eventBadge = document.getElementById('event-badge');
    const clearBtn = document.getElementById('clear-btn');

    clearBtn.addEventListener('click', () => {
      eventsContainer.innerHTML = '';
      eventsContainer.appendChild(emptyState);
    });

    function connectWs() {
      ws = new WebSocket(wsUrl);
      ws.onopen = () => {
        document.getElementById('ws-status').innerText = 'Connected (Port ' + "${port}" + ')';
        document.getElementById('ws-indicator').className = 'h-2.5 w-2.5 rounded-full bg-emerald-500 threat-pulse';
      };

      ws.onclose = () => {
        document.getElementById('ws-status').innerText = 'Reconnecting...';
        document.getElementById('ws-indicator').className = 'h-2.5 w-2.5 rounded-full bg-amber-500';
        setTimeout(connectWs, 2000);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          handleEvent(data);
        } catch {}
      };
    }

    function handleEvent(data) {
      if (emptyState && emptyState.parentNode) {
        emptyState.remove();
      }

      eventCount++;
      statTotal.innerText = eventCount;
      eventBadge.innerText = eventCount + ' events';

      const type = (data.type || 'EVENT').toUpperCase();
      const isBlock = type.includes('BLOCK') || type.includes('QUARANTINE') || type.includes('EXCEEDED');
      const isSanitize = type.includes('SANITIZE') || type.includes('SECRET');

      if (isBlock) {
        blockedCount++;
        statBlocked.innerText = blockedCount;
      }
      if (isSanitize) {
        sanitizedCount++;
        statSanitized.innerText = sanitizedCount;
      }

      const card = document.createElement('div');
      card.className = 'p-3 rounded-lg border transition-all ' + 
        (isBlock ? 'bg-rose-950/20 border-rose-500/40 text-rose-200' :
         isSanitize ? 'bg-cyan-950/20 border-cyan-500/40 text-cyan-200' :
         'bg-slate-900/80 border-slate-800 text-slate-300');

      const time = new Date().toLocaleTimeString();
      const tool = data.toolName ? '<span class="text-indigo-400 font-bold">' + data.toolName + '</span>' : '';
      const reason = data.reason ? '<div class="mt-1 text-slate-400 text-[11px] break-all">' + data.reason + '</div>' : '';
      const payload = data.payload ? '<div class="mt-1 text-slate-500 text-[10px] break-all overflow-x-auto">' + JSON.stringify(data.payload) + '</div>' : '';

      const badgeClass = isBlock ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                         isSanitize ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' :
                         'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30';

      card.innerHTML = 
        '<div class="flex items-center justify-between mb-1">' +
          '<div class="flex items-center gap-2">' +
            '<span class="px-1.5 py-0.5 rounded text-[10px] font-bold ' + badgeClass + '">' + type + '</span>' +
            tool +
          '</div>' +
          '<span class="text-[10px] text-slate-500">' + time + '</span>' +
        '</div>' +
        reason +
        payload;

      eventsContainer.prepend(card);
    }

    connectWs();
  </script>
</body>
</html>`;
}
