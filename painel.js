// ==========================================
//   PAINEL NETSIMON - JS Principal
// ==========================================

const API_BASE = "/api";

// ── Auth ──────────────────────────────────────────────────────────
function getToken()    { return localStorage.getItem("ns_token") || ""; }
function getRole()     { return localStorage.getItem("ns_role")  || ""; }
function getUsername() { return localStorage.getItem("ns_user")  || ""; }

// ── Tema (claro/escuro) ───────────────────────────────────────────
// Ícone mostra o tema que você VAI ATIVAR ao clicar (não o atual):
// sol visível = está no escuro agora, clique pra ir pro claro; lua
// visível = está no claro agora, clique pra voltar pro escuro.
function getTheme() { return localStorage.getItem("ns_theme") === "light" ? "light" : "dark"; }

function applyTheme(theme) {
  if (theme === "light") document.documentElement.setAttribute("data-theme", "light");
  else document.documentElement.removeAttribute("data-theme");
  const btn = document.getElementById("btn-theme-toggle");
  if (btn) btn.textContent = theme === "light" ? "🌙" : "☀️";
}

function toggleTheme() {
  const next = getTheme() === "light" ? "dark" : "light";
  localStorage.setItem("ns_theme", next);
  applyTheme(next);
}

async function api(path, method = "GET", body = null) {
  const opts = {
    method,
    headers: { "X-Token": getToken(), "Content-Type": "application/json" }
  };
  if (body) opts.body = JSON.stringify(body);
  try {
    const r = await fetch(API_BASE + path, opts);
    if (r.status === 401) { doLogout(); return null; }
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      toast(err.error || `Erro ${r.status}`, true);
      return null;
    }
    return await r.json();
  } catch (e) {
    toast("Erro de conexão", true);
    return null;
  }
}

async function doLogout() {
  await fetch(API_BASE + "/auth/logout", {
    method: "POST",
    headers: { "X-Token": getToken() }
  }).catch(() => {});
  // Item: antes usava localStorage.clear(), que apagava TODAS as
  // preferências do navegador junto com o login — inclusive o tema e o
  // toggle de "Monitoramento em tempo real (voz)" do Menu > IA. Como as
  // sessões do painel ficam em memória (_sessions, no Flask), reiniciar
  // o serviço netsimon-painel invalida o token de qualquer aba já
  // aberta; a próxima chamada de API cai em 401 e doLogout() era
  // chamado automaticamente — resetando essas preferências mesmo sem o
  // admin nunca ter mexido nelas. Agora só remove as chaves de
  // autenticação: as preferências continuam persistentes e só mudam se
  // o próprio usuário mudar manualmente.
  localStorage.removeItem("ns_token");
  localStorage.removeItem("ns_role");
  localStorage.removeItem("ns_user");
  window.location.href = "/login.html";
}

// ── Toast ─────────────────────────────────────────────────────────
let _toastTimer;
function toast(msg, isErr = false) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg;
  el.className = "toast show" + (isErr ? " err" : "");
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { el.className = "toast"; }, 3000);
}

// ── Impersonação (item 14): entrar no painel de um revendedor já
//    autenticado, com um jeito simples de voltar para a sessão original.
function startImpersonation(token, username) {
  const backToken = getToken();
  const backUser  = getUsername();
  const backRole  = getRole();
  if (backToken) {
    sessionStorage.setItem("ns_impersonate_back_token", backToken);
    sessionStorage.setItem("ns_impersonate_back_user", backUser);
    sessionStorage.setItem("ns_impersonate_back_role", backRole);
  }
  localStorage.setItem("ns_token", token);
  localStorage.setItem("ns_role", "reseller");
  localStorage.setItem("ns_user", username);
  window.location.href = "/dashboard.html";
}

function returnFromImpersonation() {
  const backToken = sessionStorage.getItem("ns_impersonate_back_token");
  const backUser  = sessionStorage.getItem("ns_impersonate_back_user");
  const backRole  = sessionStorage.getItem("ns_impersonate_back_role");
  if (!backToken) return;
  sessionStorage.removeItem("ns_impersonate_back_token");
  sessionStorage.removeItem("ns_impersonate_back_user");
  sessionStorage.removeItem("ns_impersonate_back_role");
  localStorage.setItem("ns_token", backToken);
  localStorage.setItem("ns_role", backRole);
  localStorage.setItem("ns_user", backUser);
  window.location.href = backRole === "admin" ? "/dashboard.html" : "/revendedores.html";
}

function injectImpersonationBanner() {
  if (!sessionStorage.getItem("ns_impersonate_back_token")) return;
  if (document.getElementById("impersonate-banner")) return;
  const banner = document.createElement("div");
  banner.id = "impersonate-banner";
  banner.className = "impersonate-banner";
  banner.innerHTML = `Você está visualizando o painel de <strong>${getUsername()}</strong> como convidado.
    <button class="btn btn-sm btn-ghost" onclick="returnFromImpersonation()">↩ Voltar ao meu painel</button>`;
  document.body.prepend(banner);
}

// ── Inicialização de página ───────────────────────────────────────
async function initPage() {
  const token = getToken();
  if (!token) { window.location.href = "/login.html"; return; }

  // Sidebar username/role
  const uEl = document.getElementById("sidebar-username");
  const rEl = document.getElementById("sidebar-role");
  if (uEl) uEl.textContent = getUsername();
  if (rEl) rEl.textContent = getRole() === "admin" ? "Administrador" : "Revendedor";

  // v30: versão do painel, discreta, no rodapé da sidebar — não polui
  // nenhuma tela nova nem exige editar as 19 páginas que compartilham
  // esse rodapé, só injeta o texto pequeno junto do usuário/role.
  const sidebarFooter = document.querySelector(".sidebar-footer .user-info div");
  if (sidebarFooter && !document.getElementById("sidebar-version")) {
    const vEl = document.createElement("div");
    vEl.id = "sidebar-version";
    vEl.textContent = "v43";
    vEl.style.cssText = "font-size:10px; opacity:.5; margin-top:2px;";
    sidebarFooter.appendChild(vEl);
  }

  // Oculta itens admin-only para revendedores
  if (getRole() !== "admin") {
    document.querySelectorAll(".admin-only").forEach(el => el.style.display = "none");
  }

  // Item 5: "Revendedores" só aparece para o admin e para revendedores
  // de nível 2 (que podem gerenciar sub-revendedores de nível 3).
  if (getRole() === "reseller") {
    const me = await api("/auth/me");
    if (me && me.can_manage_resellers === false) {
      document.querySelectorAll(".reseller-manage-only").forEach(el => el.style.display = "none");
    }
  }

  injectImpersonationBanner();

  // Marca nav item ativo
  const page = window.location.pathname.split("/").pop().replace(".html","");
  document.querySelectorAll(".nav-item").forEach(a => {
    a.classList.toggle("active", a.dataset.page === page);
  });

  // Item 3: agrupa Xray/WebSocket/SlowDNS num submenu "Gerenciar Conexões"
  injectConnGroup(page);

  // Item 6: sino de notificações no topbar
  injectNotifBell();

  // Oculta itens admin-only para revendedores (roda de novo aqui pois
  // o grupo de conexões acima foi injetado depois da primeira checagem)
  if (getRole() !== "admin") {
    document.querySelectorAll(".admin-only").forEach(el => el.style.display = "none");
  }

  // Logout
  const btnL = document.getElementById("btn-logout");
  if (btnL) btnL.addEventListener("click", doLogout);

  // Tema — o <head> já aplicou a cor certa cedo (evita flash), aqui só
  // sincroniza o ícone do botão com o tema atual
  applyTheme(getTheme());

  // Burger (mobile)
  const burger = document.getElementById("burger");
  const sidebar = document.getElementById("sidebar");
  if (burger && sidebar) {
    burger.addEventListener("click", () => sidebar.classList.toggle("open"));
    document.addEventListener("click", e => {
      if (!sidebar.contains(e.target) && !burger.contains(e.target))
        sidebar.classList.remove("open");
    });
  }

  // Item: blocos retráteis — cada card-panel marcado com data-panel-id
  // vira colapsável, lembrando o estado (aberto/fechado) por página.
  initCollapsiblePanels();
}

// ── Blocos retráteis (item pedido: abrir só o bloco de interesse no
// momento, sem a tela ficar poluída com informação que não se usa ali
// — e lembrar o estado de um acesso pro outro) ──────────────────────
// Qualquer .card-panel com data-panel-id="algum-id" vira clicável no
// header pra abrir/fechar. O estado fica salvo no localStorage,
// separado por página (usa o caminho da URL) e por bloco (o
// data-panel-id) — assim cada tela lembra exatamente quais blocos
// você deixou abertos/fechados da última vez, sem misturar com outras
// páginas nem com outros blocos de mesmo nome em telas diferentes.
function initCollapsiblePanels() {
  const panels = document.querySelectorAll(".card-panel[data-panel-id]");
  if (!panels.length) return;

  const storeKey = "ns_panels:" + location.pathname;
  let state = {};
  try { state = JSON.parse(localStorage.getItem(storeKey) || "{}"); } catch {}

  panels.forEach(panel => {
    const id = panel.dataset.panelId;
    const header = panel.querySelector(":scope > .card-panel-header");
    if (!header) return;

    if (state[id] === true) panel.classList.add("panel-collapsed");

    header.addEventListener("click", ev => {
      // Clicar num botão/switch/link/campo dentro do header (ex: "↻
      // Atualizar", o interruptor de ligar a IA) não deve abrir/fechar
      // o bloco — só clicar na área "vazia" do título faz isso.
      if (ev.target.closest("button, a, input, label, select, textarea")) return;
      panel.classList.toggle("panel-collapsed");
      state[id] = panel.classList.contains("panel-collapsed");
      try { localStorage.setItem(storeKey, JSON.stringify(state)); } catch {}
    });
  });
}

// ── Item 3: Protocolos (submenu Xray/WebSocket/SlowDNS) ────────────
// Substitui o item "Xray" da sidebar por um grupo expansível.
function injectConnGroup(page) {
  const xrayLink = document.querySelector('.nav-item[data-page="xray"]');
  if (!xrayLink || xrayLink.closest(".nav-group")) return; // já injetado ou página sem sidebar

  const groupPages = ["xray", "websocket", "slowdns"];
  const isOpen = groupPages.includes(page);
  const highlightPage = page;

  const group = document.createElement("div");
  group.className = "nav-group" + (isOpen ? " open" : "");
  group.innerHTML = `
    <button type="button" class="nav-item nav-group-toggle admin-only" title="Protocolos de conexão do servidor: Xray, WebSocket e SlowDNS">
      <span class="nav-icon nav-icon-img"><img src="/img/icon-protocolos.png" alt="Protocolos"></span><span>Protocolos</span><span class="nav-caret">▸</span>
    </button>
    <div class="nav-submenu">
      <a href="/xray.html" class="nav-item nav-sub admin-only" data-page="xray" title="Xray (VLESS/VMESS): proxy multiplataforma, mais leve e difícil de detectar por DPI"><span class="nav-icon nav-icon-img"><img src="/img/icon-xray.png" alt="Xray"></span><span>Xray</span></a>
      <a href="/websocket.html" class="nav-item nav-sub admin-only" data-page="websocket" title="WebSocket: 4 sistemas de túnel SSH — WS PROXY, WSS TLS, WSS SSH e STUNNEL SSL"><span class="nav-icon">🌐</span><span>WebSocket</span></a>
      <a href="/slowdns.html" class="nav-item nav-sub admin-only" data-page="slowdns" title="SlowDNS: túnel SSH sobre consultas DNS, útil quando só a porta 53 está liberada"><span class="nav-icon">🐌</span><span>SlowDNS</span></a>
    </div>
  `;
  xrayLink.replaceWith(group);

  group.querySelectorAll(".nav-sub").forEach(a => a.classList.toggle("active", a.dataset.page === highlightPage));
  group.querySelector(".nav-group-toggle").addEventListener("click", () => group.classList.toggle("open"));
}

// ── Item 6: Sino de notificações ────────────────────────────────────
// Avisa de forma simples e direta sobre o que importa: vencimentos
// próximos, serviços parados, desempenho ruim e servidores fora do ar.
let _lastNotifList = [];
const NOTIF_SEEN_KEY = "netsimon_seen_notif_ids";

function _getSeenNotifIds() {
  try { return new Set(JSON.parse(localStorage.getItem(NOTIF_SEEN_KEY) || "[]")); }
  catch { return new Set(); }
}
function _saveSeenNotifIds(set) {
  try { localStorage.setItem(NOTIF_SEEN_KEY, JSON.stringify([...set])); } catch {}
}

function injectNotifBell() {
  if (document.getElementById("notif-bell")) return;
  let right = document.querySelector(".topbar-right");
  if (!right) {
    const left = document.querySelector(".topbar-left");
    if (!left || !left.parentElement) return;
    right = document.createElement("div");
    right.className = "topbar-right";
    left.parentElement.appendChild(right);
  }

  const wrap = document.createElement("div");
  wrap.className = "notif-wrap";
  wrap.innerHTML = `
    <button class="notif-bell" id="notif-bell" title="Notificações">
      🔔<span class="notif-dot" id="notif-dot" style="display:none"></span>
    </button>
    <div class="notif-panel" id="notif-panel">
      <div class="notif-panel-header">Notificações</div>
      <div class="notif-list" id="notif-list"><div class="text-muted text-sm" style="padding:16px">Carregando…</div></div>
    </div>
  `;
  right.insertBefore(wrap, right.firstChild);

  document.getElementById("notif-bell").addEventListener("click", (e) => {
    e.stopPropagation();
    const panel = document.getElementById("notif-panel");
    const opening = !panel.classList.contains("open");
    panel.classList.toggle("open");
    if (opening) {
      // Ao abrir o sino, essas notificações passam a ser "vistas" — somem
      // do letreiro rolante da tela Início e da bolinha do sino até que
      // surja algo novo.
      const seen = _getSeenNotifIds();
      _lastNotifList.forEach(n => seen.add(n.id));
      _saveSeenNotifIds(seen);
      updateNotifTicker(_lastNotifList);
      updateNotifDot();
    }
  });
  document.addEventListener("click", (e) => {
    const panel = document.getElementById("notif-panel");
    if (panel && !wrap.contains(e.target)) panel.classList.remove("open");
  });

  loadNotifications();
  setInterval(loadNotifications, 45000);
}

async function loadNotifications() {
  const list = await api("/notifications");
  _lastNotifList = list || [];
  const dot = document.getElementById("notif-dot");
  const el = document.getElementById("notif-list");
  updateNotifTicker(_lastNotifList);
  updateNotifDot();
  _voiceMonitorCheck(_lastNotifList);
  if (!el) return;
  if (!list) { return; }

  if (!list.length) {
    el.innerHTML = `<div class="text-muted text-sm" style="padding:16px">Tudo certo por aqui — nenhum aviso no momento. ✅</div>`;
    return;
  }

  el.innerHTML = list.map(n => `
    <div class="notif-item notif-${n.level}">
      <span class="notif-icon">${n.icon || "ℹ️"}</span>
      <div>
        <div class="notif-title">${n.title}</div>
        <div class="notif-msg">${n.message}</div>
      </div>
    </div>
  `).join("");
}

// ── Monitoramento por voz em tempo real (item: "Jarvis" do painel) ──
// Reaproveita os MESMOS avisos que já alimentam o sino 🔔 acima (não
// cria nenhuma requisição nova nem gasta cota da IA configurada) e, se
// o admin tiver ativado o monitoramento em Menu > IA, AVISA EM VOZ ALTA
// (Web Speech API do navegador, só neste dispositivo) quando surge algo
// GENUINAMENTE NOVO — enquanto o painel estiver aberto em qualquer aba.
// Roda dentro do mesmo polling de 45s do sino (ver injectNotifBell).
const VOICE_MONITOR_KEY       = "ns_voice_monitor_enabled";
const VOICE_MONITOR_VOICE_KEY = "ns_voice_monitor_voice";
const VOICE_MONITOR_SPOKEN_KEY = "ns_voice_monitor_spoken";

function voiceMonitorEnabled() {
  return localStorage.getItem(VOICE_MONITOR_KEY) === "1";
}

function _getSpokenNotifIds() {
  try { return new Set(JSON.parse(localStorage.getItem(VOICE_MONITOR_SPOKEN_KEY) || "[]")); }
  catch { return new Set(); }
}
function _saveSpokenNotifIds(set) {
  // guarda só os últimos 300 ids pra não crescer sem limite no localStorage
  try { localStorage.setItem(VOICE_MONITOR_SPOKEN_KEY, JSON.stringify([...set].slice(-300))); } catch {}
}

// Escolhe a voz: usa a salva pelo admin em Menu > IA se existir; senão
// tenta achar automaticamente uma voz em português com nome de mulher
// (a maioria dos navegadores já traz a voz padrão de pt-BR como
// feminina, ex: "Google português do Brasil", "Microsoft Maria",
// "Luciana"); na falta de qualquer voz em pt, usa a primeira disponível.
function pickVoiceMonitorVoice() {
  if (!window.speechSynthesis) return null;
  const voices = window.speechSynthesis.getVoices() || [];
  if (!voices.length) return null;
  const savedName = localStorage.getItem(VOICE_MONITOR_VOICE_KEY);
  if (savedName) {
    const saved = voices.find(v => v.name === savedName);
    if (saved) return saved;
  }
  const ptVoices = voices.filter(v => (v.lang || "").toLowerCase().startsWith("pt"));
  const femininaPt = ptVoices.find(v => /female|mulher|maria|luciana|fernanda|joana|camila|helena/i.test(v.name));
  return femininaPt || ptVoices[0] || voices[0] || null;
}

function speakNotification(text) {
  if (!window.speechSynthesis || !text) return;
  const utter = new SpeechSynthesisUtterance(text);
  const voice = pickVoiceMonitorVoice();
  if (voice) { utter.voice = voice; utter.lang = voice.lang; }
  else { utter.lang = "pt-BR"; }
  utter.rate = 1;
  utter.pitch = 1.05;
  window.speechSynthesis.speak(utter);
}

function _voiceMonitorCheck(list) {
  if (!voiceMonitorEnabled() || !window.speechSynthesis) return;
  const spoken = _getSpokenNotifIds();
  const novos = (list || []).filter(n => !spoken.has(n.id));
  if (!novos.length) return;

  // Primeira vez que o monitor roda neste navegador: não lê em voz alta
  // um histórico inteiro que já existia antes de ativar — só define a
  // linha de base (marca como "já visto") e passa a falar dali em diante.
  if (spoken.size === 0) {
    novos.forEach(n => spoken.add(n.id));
    _saveSpokenNotifIds(spoken);
    return;
  }

  // Urgente (serviço caiu, incidente sem correção) primeiro que o resto
  const criticos = novos.filter(n => n.level === "danger");
  const resto = novos.filter(n => n.level !== "danger");
  const paraFalar = [...criticos, ...resto].slice(0, 4);
  paraFalar.forEach(n => speakNotification(`${n.title}. ${n.message}`));
  if (novos.length > paraFalar.length) {
    speakNotification(`E mais ${novos.length - paraFalar.length} ponto${novos.length - paraFalar.length > 1 ? "s" : ""} de atenção novo${novos.length - paraFalar.length > 1 ? "s" : ""}. Confira o sino de notificações.`);
  }
  novos.forEach(n => spoken.add(n.id));
  _saveSpokenNotifIds(spoken);
}

// A bolinha do sino só deve acender se existir notificação ainda NÃO
// vista — antes ela ficava presa pra sempre enquanto houvesse qualquer
// notificação ativa na API, mesmo depois de abrir o sino e "ler" tudo.
function updateNotifDot() {
  const dot = document.getElementById("notif-dot");
  if (!dot) return;
  const seen = _getSeenNotifIds();
  const hasUnseen = _lastNotifList.some(n => !seen.has(n.id));
  dot.style.display = hasUnseen ? "block" : "none";
}

// ── Letreiro de notificações (tela Início) ──────────────────────────
// Mostra em loop horizontal todas as notificações ainda não vistas (ou
// seja, que a pessoa ainda não abriu no sino) — some assim que o sino é
// aberto, e volta a aparecer se surgir alguma notificação nova depois.
function updateNotifTicker(list) {
  const wrap = document.getElementById("notif-ticker-wrap");
  const track = document.getElementById("notif-ticker-track");
  if (!wrap || !track) return; // container só existe na tela Início

  const seen = _getSeenNotifIds();
  const pending = (list || []).filter(n => !seen.has(n.id));

  if (!pending.length) {
    wrap.classList.add("empty");
    track.style.animation = "none";
    track.innerHTML = "";
    return;
  }

  const itemsHtml = pending.map(n => `
    <span class="notif-ticker-item notif-ticker-${n.level}">
      <span class="notif-ticker-icon">${n.icon || "ℹ️"}</span>
      <strong>${n.title}</strong>&nbsp;— ${n.message}
    </span>
  `).join("");
  // Conteúdo duplicado = loop contínuo sem "salto" visível no fim da volta.
  track.innerHTML = itemsHtml + itemsHtml;
  wrap.classList.remove("empty");

  requestAnimationFrame(() => {
    const singleWidth = track.scrollWidth / 2;
    const pxPerSecond = 55;
    const duration = Math.max(12, Math.round(singleWidth / pxPerSecond));
    track.style.animation = "none";
    void track.offsetWidth; // força reflow pra reiniciar a animação do zero
    track.style.animation = `notif-ticker-scroll ${duration}s linear infinite`;
  });
}


function openModal(id) {
  const m = document.getElementById(id);
  if (m) m.classList.add("open");
}

function closeModal(id) {
  const m = document.getElementById(id);
  if (m) { m.classList.remove("open"); }
}

document.addEventListener("click", e => {
  if (e.target.classList.contains("modal-overlay")) {
    e.target.classList.remove("open");
  }
});

// ── Tabs ──────────────────────────────────────────────────────────
function initTabs(containerSel) {
  const container = document.querySelector(containerSel);
  if (!container) return;
  container.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.tab;
      container.querySelectorAll(".tab-btn").forEach(b => b.classList.toggle("active", b === btn));
      container.querySelectorAll(".tab-panel").forEach(p => p.classList.toggle("active", p.id === target));
    });
  });
}

// ── Formatação de data ────────────────────────────────────────────
function fmtDate(str) {
  if (!str) return "–";
  try {
    const d = new Date(str.replace(" ", "T"));
    return d.toLocaleDateString("pt-BR") + " " + d.toLocaleTimeString("pt-BR", {hour:"2-digit",minute:"2-digit"});
  } catch { return str; }
}

function isExpired(str) {
  if (!str) return false;
  return new Date(str.replace(" ", "T")) < new Date();
}

// ── Copy to clipboard ─────────────────────────────────────────────
// navigator.clipboard só existe em contexto seguro (HTTPS ou localhost).
// Como o painel normalmente roda em HTTP puro (http://IP:81), acessar
// navigator.clipboard.writeText direto lança erro SÍNCRONO antes do
// .catch() conseguir capturar — por isso os botões de copiar pareciam
// não fazer nada. Aqui sempre validamos o contexto antes, com fallback
// via textarea+execCommand garantido para HTTP.
// ── Terminal Web (ttyd, protegido por sessão) ──────────────────────
function openTerminal() {
  window.open("/terminal/", "_blank");
}

function copyText(text) {
  try {
    if (window.isSecureContext && navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => toast("Copiado!")).catch(() => fallbackCopyText(text));
      return;
    }
  } catch (e) { /* cai no fallback abaixo */ }
  fallbackCopyText(text);
}

function fallbackCopyText(text) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    ta.style.top = "0";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    ok ? toast("Copiado!") : toast("Não foi possível copiar. Selecione e copie manualmente.", true);
  } catch (e) {
    toast("Não foi possível copiar. Selecione e copie manualmente.", true);
  }
}

// ── Confirmação simples ───────────────────────────────────────────
function confirm2(msg) {
  return window.confirm(msg);
}
