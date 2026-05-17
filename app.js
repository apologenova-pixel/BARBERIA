/**
 * ══════════════════════════════════════════════════════════════
 *  FABIOLA GESTIÓN PRO — Lógica Principal de Aplicación
 *  Sistema de Peluquería & Estética · Tecno Jump
 * ══════════════════════════════════════════════════════════════
 *
 *  MÓDULOS INTERNOS (IIFE — estado privado):
 *    §1   Constantes de seguridad (HMAC, localStorage keys, traps)
 *    §2   Formato moneda CLP
 *    §3   SHA-256 (Web Crypto API)
 *    §4   HMAC simple (firma y verificación)
 *    §5   Almacenamiento cifrado (Base64 + HMAC)
 *    §6   Sistema de bloqueo persistente (sobrevive al refresco)
 *    §7   Blindaje de herramientas de desarrollo
 *    §7b  Utilidades DOM seguras  ← NUEVO (mejora de robustez)
 *    §8   Estado privado (_data — nunca expuesto)
 *    §9   Constructor del Panel TV
 *    §10  API pública (_pub)
 *    §11  Fachada pública congelada (window.app)
 *
 *  DEPENDENCIAS:
 *    - Font Awesome 6.4 (CDN, solo íconos)
 *    - Web Crypto API (nativa del navegador — sin polyfill)
 *    - Firebase Firestore (persistencia en la nube + tiempo real)
 *
 *  PRODUCCIÓN:
 *    Este archivo ya es un módulo independiente.
 *    Cargarlo con <script src="app.js" defer></script>
 *    asegura que el DOM esté listo antes de que _pub.init() corra.
 */
(function () {
  'use strict';

  // ──────────────────────────────────────────────────────────────
  // §1  CONSTANTES DE SEGURIDAD
  // ──────────────────────────────────────────────────────────────

  // Firebase Firestore — colecciones
  const _FS_COL  = 'barberia';   // documento principal de estado
  const _FS_DOC  = 'estado';
  const _FS_HIST = 'historial';  // subcolección: cierres de caja
  const _FS_LOG  = 'auditLog';   // subcolección: auditoría de seguridad
  const _LK_KEY  = '\x66\x61\x62\x5f\x6c\x6b';                  // "fab_lk"

  // Contraseñas trampa → bloquean el sistema
  // Nota: 'admin' fue removido para permitir el usuario estándar admin/admin
  const _TRAPS   = ['0000','1111','2222','3333','4444','5555','6666',
                    '7777','8888','9999','password','root',
                    'peluqueria','123456','654321'];

  // SHA-256 de "Fabiola2025" — contraseña del primer admin
  const _DEF_HASH = 'a94fedf27e673d1e4b3c5b6c8b4f72e3ac0e4b8f2d7e1c9a4f6b2e0d8c5a1f3e';

  const _LOCK_MS  = 5 * 60 * 1000;

  // ──────────────────────────────────────────────────────────────
  // §2  FORMATO MONEDA CHILENA (CLP)
  // Formato: $15.000 con punto separador de miles
  // ──────────────────────────────────────────────────────────────
  const fmt = v => new Intl.NumberFormat('es-CL', {
    style: 'currency', currency: 'CLP', maximumFractionDigits: 0
  }).format(v || 0);

  const fmtDiff = v => v === 0 ? '—' : (v > 0 ? '▲ +' : '▼ ') + fmt(Math.abs(v));

  // ──────────────────────────────────────────────────────────────
  // §3  SHA-256 NATIVO (Web Crypto API)
  // ──────────────────────────────────────────────────────────────
  async function _sha256(msg) {
    const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  }

  // ──────────────────────────────────────────────────────────────
  // §4  PERSISTENCIA EN FIRESTORE (reemplaza localStorage + HMAC)
  // ──────────────────────────────────────────────────────────────
  // Cada escritura incluye serverTimestamp — la integridad ya no
  // depende de un secreto local sino de las Reglas de Firestore.

  async function _save(data) {
    try {
      await db.collection(_FS_COL).doc(_FS_DOC).set({
        barberos:      data.barberos      || [],
        usuarios:      data.usuarios      || [],
        servicios:     data.servicios     || [],
        espera:        data.espera        || [],
        activos:       data.activos       || [],
        pendienteCaja: data.pendienteCaja || [],
        reposo:        data.reposo        || [],
        hoy:           data.hoy           || [],
        turnos:        data.turnos        || [],
        pausa:         data.pausa         || [],
        historial:     data.historial     || [],
        _updatedAt:    firebase.firestore.FieldValue.serverTimestamp(),
        _updatedBy:    _currentUser ? _currentUser.id : 'sistema',
        _sessionId:    _sessionId,
      });
    } catch(e) {
      console.warn('[FIRESTORE] Error al guardar:', e.message);
      if (typeof _pub !== 'undefined' && _pub._toast)
        _pub._toast('\u26a0 Error de sincronización con la nube', '#ef4444');
    }
  }

  async function _load() {
    try {
      const snap = await db.collection(_FS_COL).doc(_FS_DOC).get();
      return snap.exists ? snap.data() : null;
    } catch(e) {
      console.warn('[FIRESTORE] Error al cargar:', e.message);
      return null;
    }
  }

  // §5  AUDIT LOG + SESSION ID
  // ──────────────────────────────────────────────────────────────
  const _sessionId = Date.now().toString(36) + Math.random().toString(36).substr(2, 6);

  async function _logAudit(accion, datos = {}) {
    try {
      await db.collection(_FS_LOG).add({
        accion,
        datos,
        usuario:   _currentUser ? _currentUser.nombre : 'desconocido',
        userId:    _currentUser ? _currentUser.id     : null,
        userRol:   _currentUser ? _currentUser.rol    : null,
        sessionId: _sessionId,
        timestamp: firebase.firestore.FieldValue.serverTimestamp(),
      });
    } catch(e) { console.warn('[AUDIT]', e.message); }
  }

  // ──────────────────────────────────────────────────────────────
  // §6  SISTEMA DE BLOQUEO PERSISTENTE (sobrevive al refresco)
  // ──────────────────────────────────────────────────────────────
  let _locked = false, _lockTimer = null, _failCount = 0;

  let _lockUntil = 0;
  const _saveLock  = until => { _lockUntil = until; };
  const _clearLock = ()    => { _lockUntil = 0; };
  const _readLock  = ()    => _lockUntil;

  function _triggerLock(untilTs) {
    _locked = true;
    const until = untilTs || Date.now() + _LOCK_MS;
    _saveLock(until);
    _logAudit('bloqueo_activado', { hasta: new Date(until).toISOString(), intentos: _failCount });
    _startLockUI(until);
  }

  function _startLockUI(until) {
    const overlay = document.getElementById('lockOverlay');
    const cdEl    = document.getElementById('lockCountdown');
    overlay.classList.add('active');
    if (_lockTimer) clearInterval(_lockTimer);
    _lockTimer = setInterval(() => {
      const rem = Math.max(0, Math.floor((until - Date.now()) / 1000));
      cdEl.textContent = `${String(Math.floor(rem/60)).padStart(2,'0')}:${String(rem%60).padStart(2,'0')}`;
      if (rem <= 0) {
        clearInterval(_lockTimer);
        _locked = false;
        _clearLock();
        _failCount = 0;
        overlay.classList.remove('active');
      }
    }, 500);
  }

  // Verificar bloqueo activo al cargar la página
  (function _checkPersistentLock() {
    const until = _readLock();
    if (until && Date.now() < until) { _locked = true; _startLockUI(until); }
    else if (until) _clearLock();
  })();

  // ──────────────────────────────────────────────────────────────
  // §7  BLINDAJE DE HERRAMIENTAS DE DESARROLLO
  // ──────────────────────────────────────────────────────────────
  document.addEventListener('contextmenu', e => e.preventDefault());
  document.addEventListener('keydown', e => {
    const bloq = e.key === 'F12' ||
      (e.ctrlKey && e.shiftKey && ['I','i','J','j','C','c'].includes(e.key)) ||
      (e.ctrlKey && ['U','u'].includes(e.key));
    if (bloq) { e.preventDefault(); e.stopPropagation(); return false; }
  });
  setInterval(() => {
    if (window.outerWidth - window.innerWidth > 160 || window.outerHeight - window.innerHeight > 160)
      // eslint-disable-next-line no-debugger
      debugger;
  }, 900);

  // ──────────────────────────────────────────────────────────────
  // ──────────────────────────────────────────────────────────────
  // §7b  UTILIDADES DE DOM SEGURAS
  // ──────────────────────────────────────────────────────────────
  // Mejora de robustez: en lugar de llamar document.getElementById()
  // directamente y recibir un null silencioso, estas funciones
  // fallan de forma segura y registran advertencias en consola.
  //
  // USO:
  //   _el('myId')            → elemento o null (con warning)
  //   _set('myId', '<p>…')   → innerHTML seguro
  //   _txt('myId', 'texto')  → textContent seguro
  //   _val('myId')           → .value o '' si no existe
  //   _show('myId', bool)    → toggle hidden según condición
  //   _cls('myId', cls, bool)→ classList.toggle seguro
  // ──────────────────────────────────────────────────────────────

  /**
   * Busca un elemento por ID. Registra un warning si no existe.
   * Reemplaza document.getElementById() en toda la app.
   * @param {string} id
   * @returns {HTMLElement|null}
   */
  function _el(id) {
    const el = document.getElementById(id);
    if (!el) console.warn(`[DOM] Elemento #${id} no encontrado`);
    return el;
  }

  /**
   * Establece el innerHTML de un elemento de forma segura.
   * Si el elemento no existe, no hace nada (sin crash).
   * @param {string} id
   * @param {string} html
   */
  function _set(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
  }

  /**
   * Establece el textContent de un elemento de forma segura.
   * @param {string} id
   * @param {string|number} val
   */
  function _txt(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(val ?? '');
  }

  /**
   * Lee el .value de un input de forma segura.
   * @param {string} id
   * @returns {string}
   */
  function _val(id) {
    const el = document.getElementById(id);
    return el ? el.value : '';
  }

  /**
   * Muestra u oculta un elemento agregando/quitando 'hidden'.
   * @param {string} id
   * @param {boolean} visible - true para mostrar, false para ocultar
   */
  function _show(id, visible) {
    const el = document.getElementById(id);
    if (el) el.classList.toggle('hidden', !visible);
  }

  /**
   * Hace toggle de una clase CSS de forma segura.
   * @param {string} id
   * @param {string} cls  - clase CSS a alternar
   * @param {boolean} [force] - si se provee, funciona como classList.toggle(cls, force)
   */
  function _cls(id, cls, force) {
    const el = document.getElementById(id);
    if (!el) return;
    force !== undefined
      ? el.classList.toggle(cls, force)
      : el.classList.toggle(cls);
  }

  // §8  ESTADO PRIVADO (IIFE Closure — _data nunca expuesto)
  // ──────────────────────────────────────────────────────────────
  let _data = {
    barberos:      [],  // { id, n, c, photo, userId }
    usuarios:      [],  // { id, nombre, username, hash, rol, barberoId, activo }
    servicios:     [],
    espera:        [],  // { name, price, service, target, startTime }
    activos:       [],  // { name, price, service, barber, barberoId, startTime }
    pendienteCaja: [],  // { ...activos, precioFinal, sentAt, barberoId }
    reposo:        [],
    hoy:           [],  // Registros oficiales cobrados
    turnos:        [],
    historial:     [],
    pausa:         []
  };

  let _currentUser    = null; // Usuario actualmente autenticado
  let _currentBarbero = null; // Si rol=barbero, referencia al registro de barbero
  let _tmpI    = null; // Índice temporal para modal de pago (activos)
  let _tmpRA   = null; // Índice para re-asignar cola
  let _tmpRT   = null; // Índice para retomar reposo
  let _tmpPend = null; // Índice para procesar pendiente
  let _tmpEC   = null; // Índice para enviar a caja (barbero)
  let _tmpUser = null; // ID para editar usuario
  let _photoB64 = '';  // Buffer temporal de foto
  let _monWin   = null; // Ventana del monitor TV
  let _unsubscribeSnapshot = null; // Listener onSnapshot (cancelar al logout)

  // ──────────────────────────────────────────────────────────────
  // §9  CONSTRUCTOR DEL PANEL TV
  // Genera HTML autocontenido para mostrar en televisor de sala
  // ──────────────────────────────────────────────────────────────
  function _buildMonitorHTML() {
    const turnos    = _data.turnos   || [];
    const pausa     = _data.pausa    || [];
    const activos   = _data.activos  || [];
    const espera    = _data.espera   || [];
    const barberos  = _data.barberos || [];
    const ocupados  = activos.map(a => a.barber);
    const proximo   = turnos.find(b => !ocupados.includes(b) && !pausa.includes(b));

    // Tarjeta de barbero para TV
    const barberCard = (bName, pos) => {
      const b      = barberos.find(x => x.n === bName) || {};
      const isBusy = ocupados.includes(bName);
      const isPausa= pausa.includes(bName);
      const isProx = bName === proximo;
      const cliente = activos.find(a => a.barber === bName);

      const borderColor = isProx ? '#22c55e' : isBusy ? '#ef4444' : isPausa ? '#f59e0b' : '#334155';
      const bgColor     = isProx ? '#052e16'  : isBusy ? '#1c0a0a' : isPausa ? '#1c1505' : '#0f1823';
      const glowStyle   = isProx ? 'box-shadow:0 0 24px rgba(34,197,94,.5);' : '';

      const photoEl = b.photo
        ? `<img src="${b.photo}" style="width:80px;height:80px;border-radius:50%;object-fit:cover;border:3px solid ${borderColor};margin:0 auto 10px;display:block;">`
        : `<div style="width:80px;height:80px;border-radius:50%;background:${borderColor}33;border:3px solid ${borderColor};color:${borderColor};font-size:2rem;font-weight:900;display:flex;align-items:center;justify-content:center;margin:0 auto 10px;">${bName.charAt(0)}</div>`;

      const statusBadge = isProx
        ? `<div style="background:#16a34a;color:#fff;padding:5px 14px;border-radius:999px;font-size:9px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;display:inline-block;animation:pulse 1.8s infinite;">● PRÓXIMO</div>`
        : isBusy
        ? `<div style="background:#7f1d1d;color:#fca5a5;padding:5px 14px;border-radius:999px;font-size:9px;font-weight:900;text-transform:uppercase;display:inline-block;">✂ EN ATENCIÓN</div>`
        : isPausa
        ? `<div style="background:#78350f;color:#fde68a;padding:5px 14px;border-radius:999px;font-size:9px;font-weight:900;text-transform:uppercase;display:inline-block;">⏸ PAUSA</div>`
        : `<div style="background:#14532d;color:#86efac;padding:5px 14px;border-radius:999px;font-size:9px;font-weight:900;text-transform:uppercase;display:inline-block;">○ LIBRE</div>`;

      return `
        <div style="background:${bgColor};border:2px solid ${borderColor};${glowStyle}border-radius:20px;padding:20px 16px;text-align:center;position:relative;animation:slideIn .4s ease;">
          ${isProx ? `<div style="position:absolute;top:-11px;left:50%;transform:translateX(-50%);background:#16a34a;color:#fff;padding:2px 14px;border-radius:999px;font-size:8px;font-weight:900;text-transform:uppercase;letter-spacing:.1em;white-space:nowrap;">✦ PRÓXIMO ✦</div>` : ''}
          <div style="font-size:10px;color:#475569;font-weight:900;margin-bottom:8px;letter-spacing:.1em;">#${pos + 1} EN FILA</div>
          ${photoEl}
          <div style="font-size:17px;font-weight:900;color:#f1f5f9;text-transform:uppercase;margin-bottom:6px;">${bName}</div>
          ${isBusy && cliente ? `<div style="font-size:10px;color:#94a3b8;margin-bottom:6px;font-weight:700;">→ ${cliente.name}</div>` : ''}
          ${statusBadge}
        </div>`;
    };

    // Filas de espera
    const esperaRows = espera.map((c, i) => `
      <div style="display:flex;align-items:center;gap:14px;padding:12px 18px;background:#0f1f12;border-radius:14px;border:1px solid #14532d;margin-bottom:8px;animation:slideIn .3s ease;">
        <div style="width:34px;height:34px;border-radius:50%;background:#14532d;color:#86efac;font-size:13px;font-weight:900;display:flex;align-items:center;justify-content:center;flex-shrink:0;">${i+1}</div>
        <div style="flex:1;">
          <div style="font-size:16px;font-weight:900;color:#f1f5f9;text-transform:uppercase;">${c.name}</div>
          <div style="font-size:9px;color:#475569;font-weight:700;text-transform:uppercase;margin-top:2px;">
            ${c.target === 'S/A' ? 'Cualquier profesional' : 'Solicita: ' + c.target}
          </div>
        </div>
        <div style="background:#1c2a10;color:#86efac;padding:4px 12px;border-radius:999px;font-size:9px;font-weight:900;text-transform:uppercase;">En espera</div>
      </div>`).join('');

    const hora = new Date().toLocaleTimeString('es-CL', { hour:'2-digit', minute:'2-digit' });

    return `<!DOCTYPE html><html lang="es"><head>
      <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
      <title>Fabiola · Sala de Espera</title>
      <style>
        *{margin:0;padding:0;box-sizing:border-box;}
        body{font-family:'Inter',system-ui,sans-serif;background:#030f1a;color:#f8fafc;min-height:100vh;padding:32px;}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
        @keyframes slideIn{from{transform:translateY(16px);opacity:0}to{transform:translateY(0);opacity:1}}
      </style>
    </head><body>
      <div style="max-width:1300px;margin:0 auto;">
        <!-- Encabezado -->
        <div style="display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:36px;">
          <div>
            <div style="font-size:10px;font-weight:900;color:#22c55e;letter-spacing:.3em;text-transform:uppercase;margin-bottom:4px;">Peluquería & Estética</div>
            <div style="font-size:3rem;font-weight:900;letter-spacing:-.04em;">FABIOLA<span style="color:#22c55e;">.</span></div>
          </div>
          <div style="text-align:right;">
            <div id="monClock" style="font-size:2.4rem;font-weight:900;color:#22c55e;font-family:monospace;">${hora}</div>
            <div style="font-size:9px;color:#475569;font-weight:700;text-transform:uppercase;margin-top:2px;">San Martin 443, Castro</div>
          </div>
        </div>

        <!-- Turno de Profesionales -->
        <div style="margin-bottom:36px;">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:18px;">
            <i style="font-size:11px;color:#22c55e;">✂</i>
            <span style="font-size:10px;font-weight:900;color:#22c55e;letter-spacing:.25em;text-transform:uppercase;">Profesionales en Fila de Turno</span>
          </div>
          ${turnos.length
            ? `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:14px;">${turnos.map((b,i) => barberCard(b,i)).join('')}</div>`
            : `<div style="text-align:center;padding:48px;background:#0f1823;border-radius:20px;color:#334155;font-weight:900;text-transform:uppercase;font-size:12px;">Sin profesionales en turno</div>`
          }
        </div>

        <!-- Cola de Espera -->
        <div>
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:18px;">
            <span style="font-size:10px;font-weight:900;color:#f59e0b;letter-spacing:.25em;text-transform:uppercase;">⏳ Cola de Espera</span>
            <span style="background:#1c1505;color:#f59e0b;padding:2px 10px;border-radius:999px;font-size:9px;font-weight:900;">${espera.length}</span>
          </div>
          ${espera.length
            ? esperaRows
            : `<div style="text-align:center;padding:32px;background:#0f1823;border-radius:16px;color:#334155;font-weight:900;text-transform:uppercase;font-size:11px;">Sin clientes en espera</div>`
          }
        </div>

        <div style="text-align:center;margin-top:48px;font-size:9px;color:#1e293b;font-weight:700;text-transform:uppercase;letter-spacing:.1em;">
          Sistema por Tecno Jump
        </div>
      </div>
      <script>
        // Reloj en vivo del monitor TV
        setInterval(function(){
          var el = document.getElementById('monClock');
          if(el) el.textContent = new Date().toLocaleTimeString('es-CL',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
        }, 1000);
      <\/script>
    </body></html>`;
  }

  // ──────────────────────────────────────────────────────────────
  // §10  API PÚBLICA (_pub — nunca expuesto directamente)
  // ──────────────────────────────────────────────────────────────
  const _pub = {

    // ──── §10.1 INICIALIZACIÓN ────────────────────────────────
    async init() {
      // Carga inicial desde Firestore
      try {
        const loaded = await _load();
        if (loaded) {
          _data = loaded;
          const defaults = { reposo:[], pausa:[], historial:[], usuarios:[],
                             pendienteCaja:[], turnos:[], activos:[], espera:[] };
          Object.keys(defaults).forEach(k => { if (!_data[k]) _data[k] = defaults[k]; });
          _data.barberos.forEach(b => { if (!b.id) b.id = 'b_' + Math.random().toString(36).substr(2,8); });
        }
      } catch(e) { console.warn('[INIT] Error cargando datos:', e.message); }

      // Usuario administrador por defecto (admin / 1234)
      if (!_data.usuarios || !_data.usuarios.length) {
        const h = await _sha256('1234');
        _data.usuarios.push({ id:'u_admin_001', nombre:'Administrador',
          username:'admin', hash:h, rol:'admin', barberoId:null, activo:true });
        await _save(_data);
      }

      // Fechas por defecto en panel Staff
      const now = new Date();
      const fhEl = document.getElementById('fechaHasta');
      const fdEl = document.getElementById('fechaDesde');
      if (fhEl) fhEl.value = now.toISOString().split('T')[0];
      if (fdEl) { const w = new Date(); w.setDate(w.getDate()-7); fdEl.value = w.toISOString().split('T')[0]; }

      // ── onSnapshot: sincronización en tiempo real ──────────────
      _unsubscribeSnapshot = db.collection(_FS_COL).doc(_FS_DOC)
        .onSnapshot(snap => {
          if (!snap.exists || !_currentUser) return;
          const r = snap.data();
          _data = {
            barberos:r.barberos||[], usuarios:r.usuarios||[], servicios:r.servicios||[],
            espera:r.espera||[], activos:r.activos||[], pendienteCaja:r.pendienteCaja||[],
            reposo:r.reposo||[], hoy:r.hoy||[], turnos:r.turnos||[],
            pausa:r.pausa||[], historial:r.historial||[],
          };
          _pub._syncFromFirestore();
        }, err => { console.warn('[SNAPSHOT]', err.message); });

      // Monitor TV y timers
      setInterval(() => {
        if (_monWin && !_monWin.closed) {
          try { _monWin.document.open(); _monWin.document.write(_buildMonitorHTML()); _monWin.document.close(); } catch(e) {}
        }
      }, 5000);
      setInterval(() => _pub.updateTimers(), 1000);
    },

    // Sincroniza la vista activa cuando onSnapshot recibe cambios remotos
    _syncFromFirestore() {
      if (!_currentUser) return;
      const rol = _currentUser.rol;
      if (rol === 'admin')   { _pub.render(); _pub.renderCaja(); _pub.renderPendiente(); }
      else if (rol === 'cajero')  _pub.renderCajero();
      else if (rol === 'barbero') _pub.renderBarbero();
    },

    save() { return _save(_data); },

    // ──── §10.2 AUTENTICACIÓN ──────────────────────────────────
    async login() {
      if (_locked) return;
      const usr  = document.getElementById('loginUser').value.trim().toLowerCase();
      const pass = document.getElementById('loginPass').value;
      const errEl = document.getElementById('loginErr');

      // Verificar contraseña trampa (honeypot)
      if (_TRAPS.includes(pass.toLowerCase())) {
        errEl.textContent = '⚠ Código trampa. Bloqueado 5 minutos.';
        errEl.classList.remove('hidden');
        _triggerLock(); return;
      }

      const hash  = await _sha256(pass);
      const user  = _data.usuarios.find(u => u.username === usr && u.hash === hash && u.activo !== false);

      if (user) {
        _failCount   = 0;
        _currentUser = user;
        _logAudit('login_exitoso', { username: usr, rol: user.rol });
        _currentBarbero = user.rol === 'barbero'
          ? (_data.barberos.find(b => b.id === user.barberoId) || null)
          : null;
        errEl.classList.add('hidden');
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('app-content').classList.remove('hidden');
        _pub.renderNav();
      } else {
        _failCount++;
        if (_failCount >= 5) {
          errEl.textContent = '⚠ Demasiados intentos. Bloqueado 5 min.';
          errEl.classList.remove('hidden');
          _logAudit('bloqueo_por_intentos', { username: usr });
          _triggerLock(); _failCount = 0;
        } else {
          _logAudit('login_fallido', { username: usr, intento: _failCount });
          errEl.textContent = `Usuario o contraseña incorrectos. (${_failCount}/5)`;
          errEl.classList.remove('hidden');
        }
      }
    },

    logout() {
      if (_unsubscribeSnapshot) { _unsubscribeSnapshot(); _unsubscribeSnapshot = null; }
      _logAudit('logout', {});
      _currentUser    = null;
      _currentBarbero = null;
      document.getElementById('app-content').classList.add('hidden');
      document.getElementById('login-screen').classList.remove('hidden');
      document.getElementById('loginUser').value = '';
      document.getElementById('loginPass').value = '';
      document.getElementById('loginErr').classList.add('hidden');
    },

    // Renderiza la navegación según el rol autenticado
    renderNav() {
      if (!_currentUser) return;
      const isAdmin   = _currentUser.rol === 'admin';
      const isBarbero = _currentUser.rol === 'barbero';
      const isCajero  = _currentUser.rol === 'cajero';

      // Mostrar nombre/avatar en nav
      document.getElementById('navAvatar').textContent = _currentUser.nombre.charAt(0).toUpperCase();
      document.getElementById('navNombre').textContent = _currentUser.nombre;

      // Colorear avatar según rol
      const avatarEl = document.getElementById('navAvatar');
      avatarEl.className = 'w-7 h-7 rounded-full flex items-center justify-center font-black text-xs ' +
        (isAdmin   ? 'bg-emerald-100 text-emerald-700' :
         isCajero  ? 'bg-sky-100 text-sky-700' :
                     'bg-blue-100 text-blue-700');

      // Alternar secciones del nav
      document.getElementById('adminNav').classList.toggle('hidden', !isAdmin);
      document.getElementById('barberoNav').classList.toggle('hidden', !isBarbero);
      document.getElementById('cajeroNav').classList.toggle('hidden', !isCajero);

      // Ocultar todas las vistas antes de activar la correcta
      ['t-atencion','t-caja','t-staff','t-config','t-usuarios','t-barbero','t-cajero','t-estadisticas'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.add('hidden');
      });

      // Tab estadísticas solo para admin
      const tabStats = document.getElementById('tabEstadisticas');
      if (tabStats) tabStats.classList.toggle('hidden', !isAdmin);

      if (isAdmin) {
        document.getElementById('tabAtencion').click();
        _pub.render();
        _pub.renderCaja();
      } else if (isCajero) {
        document.getElementById('tabCajeroPanel').click();
        _pub.renderCajero();
      } else {
        // Barbero
        document.getElementById('t-barbero').classList.remove('hidden');
        _pub.renderBarbero();
      }
    },

    tab(t, btn) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      if (btn) btn.classList.add('active');
      ['t-atencion','t-caja','t-staff','t-config','t-usuarios','t-barbero','t-cajero','t-estadisticas'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.add('hidden');
      });
      const section = document.getElementById(`t-${t}`);
      if (section) section.classList.remove('hidden');
      if (t === 'caja')         { _pub.renderCaja(); _pub.renderPendiente(); }
      if (t === 'usuarios')     { _pub.renderAdmin(); }
      if (t === 'cajero')       { _pub.renderCajero(); }
      if (t === 'estadisticas') { _pub.renderEstadisticas('hoy'); }
    },

    // ──── §10.3 PANEL DE ADMINISTRACIÓN DE USUARIOS ──────────
    renderAdmin() {
      const us = _data.usuarios;
      document.getElementById('uTotalCnt').textContent   = us.length;
      document.getElementById('uAdminCnt').textContent   = us.filter(u => u.rol === 'admin').length;
      document.getElementById('uBarberoCnt').textContent = us.filter(u => u.rol === 'barbero').length;
      // Mostrar cajeros si el elemento existe (se añade dinámicamente)
      const cajEl = document.getElementById('uCajeroCnt');
      if (cajEl) cajEl.textContent = us.filter(u => u.rol === 'cajero').length;

      const roleColors = {
        admin:   'text-emerald-600 bg-emerald-50',
        barbero: 'text-blue-600 bg-blue-50',
        cajero:  'text-sky-600 bg-sky-50'
      };
      const roleLabels = {
        admin:   '🛡 Admin',
        barbero: '✂ Profesional',
        cajero:  '💰 Cajero'
      };

      document.getElementById('usersList').innerHTML = us.map(u => {
        const linked = u.barberoId ? _data.barberos.find(b => b.id === u.barberoId) : null;
        const av = linked && linked.photo
          ? `<img src="${linked.photo}" class="av48">`
          : `<div class="av-ph">${u.nombre.charAt(0)}</div>`;
        const esYo = _currentUser && u.id === _currentUser.id;

        return `
          <div class="bg-white p-4 rounded-2xl border border-slate-100 shadow-sm flex items-center gap-4">
            ${av}
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 flex-wrap">
                <span class="font-black text-sm uppercase truncate">${u.nombre}</span>
                <span class="px-2 py-0.5 rounded-full text-[8px] font-black ${roleColors[u.rol]}">${roleLabels[u.rol]}</span>
                ${esYo ? '<span class="px-2 py-0.5 rounded-full text-[8px] font-black bg-slate-100 text-slate-500">Tú</span>' : ''}
                ${u.activo === false ? '<span class="px-2 py-0.5 rounded-full text-[8px] font-black bg-red-100 text-red-500">Inactivo</span>' : ''}
              </div>
              <div class="text-[10px] text-slate-400 font-bold mt-0.5">@${u.username}${linked ? ` · Vinculado a: ${linked.n}` : ''}</div>
            </div>
            <div class="flex gap-2 flex-shrink-0">
              ${u.rol === 'admin' && !esYo ? `<button onclick="app.openUserModal('${u.id}')"
                class="w-8 h-8 flex items-center justify-center rounded-lg bg-slate-50 text-slate-400 hover:bg-emerald-500 hover:text-white transition-all text-xs">
                <i class="fas fa-pen"></i></button>` : ''}
              ${!esYo ? `<button onclick="app.toggleUserActive('${u.id}')"
                class="w-8 h-8 flex items-center justify-center rounded-lg ${u.activo === false ? 'bg-green-50 text-green-500 hover:bg-green-500' : 'bg-slate-50 text-slate-400 hover:bg-amber-500'} hover:text-white transition-all text-xs">
                <i class="fas ${u.activo === false ? 'fa-user-check' : 'fa-user-slash'}"></i></button>` : ''}
              ${u.rol === 'admin' && !esYo ? `<button onclick="app.deleteUser('${u.id}')"
                class="w-8 h-8 flex items-center justify-center rounded-lg bg-slate-50 text-red-400 hover:bg-red-500 hover:text-white transition-all text-xs">
                <i class="fas fa-trash"></i></button>` : ''}
            </div>
          </div>`;
      }).join('');
    },

    openUserModal(id) {
      _tmpUser = id;
      if (id) {
        const u = _data.usuarios.find(x => x.id === id);
        if (!u) return;
        document.getElementById('umTitle').textContent = 'Editar Usuario';
        document.getElementById('umNombre').value = u.nombre;
        document.getElementById('umUser').value   = u.username;
        document.getElementById('umPass').value   = '';
        document.getElementById('umId').value     = id;
        document.getElementById('umRol').value    = u.rol;
      } else {
        document.getElementById('umTitle').textContent = 'Nuevo Usuario de Sistema';
        document.getElementById('umNombre').value = '';
        document.getElementById('umUser').value   = '';
        document.getElementById('umPass').value   = '';
        document.getElementById('umId').value     = '';
        document.getElementById('umRol').value    = 'cajero';
      }
      _pub.openM('mUserModal');
    },

    async saveAdminUser() {
      const nombre = document.getElementById('umNombre').value.trim();
      const user   = document.getElementById('umUser').value.trim().toLowerCase();
      const pass   = document.getElementById('umPass').value;
      const id     = document.getElementById('umId').value;
      const rol    = document.getElementById('umRol').value || 'cajero';

      if (!nombre || !user) return _pub._toast('Nombre y usuario son requeridos', '#ef4444');
      if (!id && !pass)     return _pub._toast('La contraseña es requerida para nuevos usuarios', '#ef4444');
      if (pass && _TRAPS.includes(pass.toLowerCase())) return _pub._toast('Contraseña no permitida', '#ef4444');

      const dup = _data.usuarios.find(u => u.username === user && u.id !== id);
      if (dup) return _pub._toast('Ese nombre de usuario ya existe', '#ef4444');

      if (id) {
        const u = _data.usuarios.find(x => x.id === id);
        u.nombre   = nombre;
        u.username = user;
        u.rol      = rol;
        if (pass) u.hash = await _sha256(pass);
      } else {
        const hash = await _sha256(pass);
        _data.usuarios.push({
          id: 'u_' + Date.now(), nombre, username: user,
          hash, rol, barberoId: null, activo: true
        });
      }
      _pub.closeM();
      _pub.save();
      _pub.renderAdmin();
      _pub._toast('Usuario guardado correctamente', '#16a34a');
    },

    deleteUser(id) {
      if (!id) return;
      const u = _data.usuarios.find(x => x.id === id);
      if (!u) return;
      if (u.id === _currentUser?.id) return _pub._toast('No puedes eliminarte a ti mismo', '#ef4444');
      if (u.rol === 'admin' && _data.usuarios.filter(x => x.rol === 'admin').length <= 1)
        return _pub._toast('Debe existir al menos un administrador', '#ef4444');
      if (!confirm(`¿Eliminar acceso de "${u.nombre}"?`)) return;
      _data.usuarios = _data.usuarios.filter(x => x.id !== id);
      _pub.save(); _pub.renderAdmin();
      _pub._toast('Usuario eliminado', '#64748b');
    },

    toggleUserActive(id) {
      const u = _data.usuarios.find(x => x.id === id);
      if (!u) return;
      u.activo = (u.activo === false) ? true : false;
      _pub.save(); _pub.renderAdmin();
      _pub._toast(u.activo ? `${u.nombre} habilitado` : `${u.nombre} deshabilitado`, '#f59e0b');
    },

    // ──── §10.4b VISTA DE CAJERO ──────────────────────────────
    // Renderiza el panel del cajero: cola + activos + pendiente
    renderCajero() {
      // ── Selects de recepción del cajero ──
      const inS = document.getElementById('cjInS');
      const inT = document.getElementById('cjInTarget');
      if (inS) inS.innerHTML = '<option value="">Seleccionar Servicio...</option>' +
        _data.servicios.map(s => `<option value="${s.n}">${s.n}</option>`).join('');
      if (inT) inT.innerHTML = '<option value="S/A">CUALQUIER PROFESIONAL</option>' +
        _data.barberos.map(b => `<option value="${b.n}">PEDIR A: ${b.n.toUpperCase()}</option>`).join('');

      // ── Cola de espera ──
      const colaEl   = document.getElementById('cjCola');
      const waitCnt  = document.getElementById('cjWaitCnt');
      if (waitCnt) waitCnt.textContent = _data.espera.length;
      if (colaEl) {
        colaEl.innerHTML = _data.espera.length
          ? _data.espera.map((c, i) => `
              <div class="p-4 bg-slate-50 border border-slate-100 rounded-2xl">
                <div class="flex justify-between items-start">
                  <div>
                    <b class="text-[12px] uppercase">${c.name}</b><br>
                    <small class="text-[8px] font-black text-sky-600">
                      ${c.target === 'S/A' ? 'ORDEN DE TURNO' : 'SOLICITA: ' + c.target}
                    </small>
                  </div>
                  <button onclick="app.rmEspera(${i});app.renderCajero();"
                    class="text-red-200 hover:text-red-500 text-xs"><i class="fas fa-minus-circle"></i></button>
                </div>
              </div>`).join('')
          : '<p class="text-slate-300 text-[10px] font-black uppercase text-center py-6">Sin clientes en espera</p>';
      }

      // ── Pendiente de cobro ──
      const pend    = _data.pendienteCaja || [];
      const pSec    = document.getElementById('cjPendienteSection');
      const pList   = document.getElementById('cjPendienteList');
      const pCnt    = document.getElementById('cjPendienteCnt');
      if (pCnt)  pCnt.textContent  = pend.length;
      if (pSec)  pSec.classList.toggle('hidden', !pend.length);
      if (pList) {
        pList.innerHTML = pend.map((p, i) => {
          const b = _data.barberos.find(x => x.id === p.barberoId);
          return `
            <div class="bg-white p-4 rounded-2xl border border-amber-100 shadow-sm">
              <div class="flex justify-between items-start mb-2">
                <div>
                  <p class="font-black text-sm uppercase">${p.name}</p>
                  <p class="text-[9px] text-slate-400 font-bold uppercase">${p.service || ''} · ${b ? b.n : 'N/A'}</p>
                </div>
                <span class="font-black text-emerald-700 text-sm">${fmt(p.precioFinal)}</span>
              </div>
              <button onclick="app.procesarPendiente(${i})"
                class="w-full bg-amber-500 hover:bg-amber-600 text-white py-2 rounded-xl text-[9px] font-black uppercase transition-all">
                <i class="fas fa-cash-register mr-1"></i>Cobrar
              </button>
            </div>`;
        }).join('');
      }

      // ── Activos (sillas en atención) ──
      const sillasEl  = document.getElementById('cjSillas');
      const activosCnt = document.getElementById('cjActivosCnt');
      if (activosCnt) activosCnt.textContent = `${_data.activos.length} activos`;
      if (sillasEl) {
        sillasEl.innerHTML = _data.activos.length
          ? _data.activos.map((a, i) => {
              const bObj = _data.barberos.find(x => x.n === a.barber);
              const av   = bObj?.photo
                ? `<img src="${bObj.photo}" class="av64 mx-auto mb-2">`
                : `<div class="av-ph mx-auto mb-2" style="width:52px;height:52px;font-size:1.3rem;">${a.barber.charAt(0)}</div>`;
              return `
                <div class="bg-white p-5 rounded-3xl border border-slate-100 text-center shadow-lg">
                  ${av}
                  <p class="text-[9px] font-black text-sky-600 uppercase mb-1">${a.barber}</p>
                  <h4 class="font-black text-slate-800 uppercase text-lg mb-1">${a.name}</h4>
                  <p class="text-[8px] text-slate-400 uppercase mb-2">${a.service || ''}</p>
                  <div class="timer mb-4" id="timer-${i}">00:00</div>
                  <button onclick="app.prepP(${i})"
                    class="w-full bg-slate-900 text-white py-2 rounded-xl text-[9px] font-black uppercase hover:bg-sky-600 transition-all">
                    <i class="fas fa-check mr-1"></i>Cobrar
                  </button>
                </div>`;
            }).join('')
          : '<div class="col-span-3 text-center text-slate-300 text-[10px] font-black uppercase py-10">Sin clientes en atención</div>';
      }
    },

    // Agrega un cliente a la fila desde la vista de cajero
    regCajero() {
      const n = document.getElementById('cjInN').value.trim();
      const p = document.getElementById('cjInP').value;
      const t = document.getElementById('cjInTarget').value;
      if (!n || !p) return _pub._toast('Ingresa nombre y precio', '#ef4444');

      const ocupados = _data.activos.map(a => a.barber);
      const pausa    = _data.pausa || [];
      const cliente  = {
        name: n, price: parseInt(p),
        service: document.getElementById('cjInS').value,
        target: t, startTime: Date.now()
      };
      let asignado = false;

      if (t !== 'S/A') {
        if (!ocupados.includes(t) && !pausa.includes(t) && _data.turnos.includes(t)) {
          const bObj = _data.barberos.find(b => b.n === t);
          _data.activos.push({ ...cliente, barber: t, barberoId: bObj?.id || null });
          asignado = true;
        }
      } else {
        const libre = _data.turnos.find(b => !ocupados.includes(b) && !pausa.includes(b));
        if (libre) {
          const bObj = _data.barberos.find(b => b.n === libre);
          _data.activos.push({ ...cliente, barber: libre, barberoId: bObj?.id || null });
          asignado = true;
        }
      }

      if (!asignado) {
        _data.espera.push(cliente);
        _pub._toast('Todos ocupados — cliente en cola', '#f59e0b');
      }

      document.getElementById('cjInN').value = '';
      document.getElementById('cjInP').value = '';
      _pub.save(); _pub.renderCajero();
    },

    // Actualiza el precio según el servicio seleccionado en la vista cajero
    priceCajero() {
      const s = _data.servicios.find(x => x.n === document.getElementById('cjInS').value);
      if (s) document.getElementById('cjInP').value = s.p;
    },
    renderBarbero() {
      if (!_currentBarbero) return;
      const b       = _currentBarbero;
      const turnos  = _data.turnos || [];
      const pausa   = _data.pausa  || [];
      const pos     = turnos.indexOf(b.n); // posición en la fila (0 = primero)
      const activo  = _data.activos.find(a => a.barber === b.n);
      const enPausa = pausa.includes(b.n);

      // ── Tarjeta de estado en turno ──
      let turnoHtml, turnoClass;
      if (!turnos.includes(b.n)) {
        turnoHtml  = `<p class="text-slate-400 text-sm font-bold uppercase">No estás en turno hoy</p>`;
        turnoClass = 'bg-white border-2 border-slate-100';
      } else if (activo) {
        turnoHtml  = `<div class="flex items-center gap-4">
          <i class="fas fa-cut text-red-500 text-3xl animate-pulse"></i>
          <div><p class="text-[10px] font-black uppercase text-red-500">En Atención</p>
          <p class="font-black text-2xl uppercase">${activo.name}</p>
          <p class="text-[10px] text-slate-400 font-bold">${activo.service || ''}</p></div>
        </div>`;
        turnoClass = 'bg-red-50 border-2 border-red-200';
      } else if (enPausa) {
        turnoHtml  = `<div class="flex items-center gap-4">
          <i class="fas fa-pause-circle text-amber-500 text-3xl"></i>
          <div><p class="text-[10px] font-black uppercase text-amber-600">En Pausa</p>
          <p class="font-black text-xl text-amber-800">Regresa cuando estés listo</p></div>
        </div>`;
        turnoClass = 'bg-amber-50 border-2 border-amber-200';
      } else {
        const posOcupados  = _data.activos.map(a => a.barber);
        const posEnFila    = turnos.filter(t => !posOcupados.includes(t) && !pausa.includes(t));
        const miPosLibre   = posEnFila.indexOf(b.n) + 1;
        turnoHtml  = `<div class="flex items-center gap-4">
          <div class="bg-emerald-100 text-emerald-700 w-14 h-14 rounded-2xl flex items-center justify-center font-black text-2xl">#${miPosLibre}</div>
          <div><p class="text-[10px] font-black uppercase text-emerald-600">${miPosLibre === 1 ? '🟢 Próximo en Atender' : 'Libre en Fila'}</p>
          <p class="font-black text-xl text-emerald-800">Posición ${miPosLibre} de ${posEnFila.length}</p></div>
        </div>`;
        turnoClass = 'bg-emerald-50 border-2 border-emerald-200';
      }
      document.getElementById('miTurnoCard').className = `rounded-3xl p-6 border-2 shadow-md ${turnoClass}`;
      document.getElementById('miTurnoCard').innerHTML = turnoHtml;

      // ── Mis clientes activos ──
      const misActivos = _data.activos
        .map((a, i) => ({ ...a, idx: i }))
        .filter(a => a.barber === b.n);
      document.getElementById('misClientesCnt').textContent = misActivos.length;

      if (misActivos.length) {
        document.getElementById('misClientes').innerHTML = misActivos.map(a => `
          <div class="bg-white p-5 rounded-3xl border border-slate-100 text-center shadow">
            <p class="text-[9px] font-black text-emerald-600 uppercase mb-1">En atención</p>
            <h4 class="font-black text-slate-800 uppercase text-xl mb-1">${a.name}</h4>
            <p class="text-[9px] text-slate-400 uppercase mb-3">${a.service || ''}</p>
            <div class="timer mb-4" id="timer-${a.idx}">00:00</div>
            <button onclick="app.openEnviarCaja(${a.idx})"
              class="w-full bg-amber-500 hover:bg-amber-600 text-white py-3 rounded-xl text-[10px] font-black uppercase transition-all">
              <i class="fas fa-paper-plane mr-2"></i>Enviar a Caja
            </button>
          </div>`).join('');
      } else {
        document.getElementById('misClientes').innerHTML =
          `<p class="text-slate-300 text-[10px] font-black uppercase col-span-2 text-center py-8">Sin clientes asignados ahora</p>`;
      }

      // ── Historial del día del barbero ──
      const pendMio = (_data.pendienteCaja || []).filter(p => p.barberoId === b.id);
      const pagMio  = (_data.hoy || []).filter(h => h.barber === b.n && !h.type);
      const histAll = [
        ...pendMio.map(p => ({ ...p, _estado: 'pendiente' })),
        ...pagMio.map(p  => ({ ...p, _estado: 'cobrado'   }))
      ].sort((a, z) => (z.sentAt || z.timestamp || 0) - (a.sentAt || a.timestamp || 0));

      const totalDia = histAll.reduce((s, h) => s + (h.precioFinal || h.price || 0), 0);
      document.getElementById('miTotalDia').textContent = fmt(totalDia);

      if (histAll.length) {
        document.getElementById('miHistorialBody').innerHTML = histAll.map(h => `
          <tr class="hover:bg-slate-50">
            <td class="p-3 font-black uppercase text-sm">${h.name}</td>
            <td class="p-3 text-slate-500 text-xs font-bold">${h.service || '—'}</td>
            <td class="p-3 text-right font-black text-emerald-700">${fmt(h.precioFinal || h.price)}</td>
            <td class="p-3 text-center">
              ${h._estado === 'pendiente'
                ? '<span class="badge-pend">En caja</span>'
                : '<span class="badge-cobrado">Cobrado</span>'}
            </td>
          </tr>`).join('');
      } else {
        document.getElementById('miHistorialBody').innerHTML =
          `<tr><td colspan="4" class="text-center text-slate-300 py-8 font-black uppercase text-[10px]">Sin servicios hoy</td></tr>`;
      }
    },

    // Abre modal para que el barbero ingrese precio y envíe a caja
    openEnviarCaja(idx) {
      _tmpEC = idx;
      const a = _data.activos[idx];
      if (!a) return;
      document.getElementById('ecClienteName').textContent = `${a.name} · ${a.service || 'Servicio'}`;
      document.getElementById('ecPrecio').value = a.price || '';
      _pub.openM('mEnviarCaja');
    },

    async confirmarEnviarCaja() {
      if (_tmpEC === null) return;
      const item        = _data.activos.splice(_tmpEC, 1)[0];
      const precioFinal = parseInt(document.getElementById('ecPrecio').value) || item.price;

      // Mover a pendienteCaja con datos completos
      _data.pendienteCaja.push({
        ...item,
        precioFinal,
        barberoId: _currentBarbero.id,
        sentAt: Date.now()
      });

      // Liberar al barbero: lo mueve al final de la fila de turno
      const b = item.barber;
      _data.turnos = [..._data.turnos.filter(t => t !== b), b];

      _tmpEC = null;
      _pub.closeM();
      _pub.save();
      _pub.renderBarbero();
      _pub._toast('Enviado a caja correctamente ✓', '#f59e0b');
    },

    // ──── §10.5 PENDIENTE DE CAJA (Admin procesa pagos de barberos) ──
    renderPendiente() {
      const pend = _data.pendienteCaja || [];

      // — Sección en t-caja —
      const sec  = document.getElementById('pendienteSection');
      const list = document.getElementById('pendienteList');
      const cnt  = document.getElementById('pendienteCnt');
      if (sec) {
        if (!pend.length) { sec.classList.add('hidden'); }
        else {
          sec.classList.remove('hidden');
          cnt.textContent = pend.length;
          list.innerHTML = pend.map((p, i) => {
            const b = _data.barberos.find(x => x.id === p.barberoId);
            return `
              <div class="bg-white p-4 rounded-2xl border border-amber-100 shadow-sm">
                <div class="flex justify-between items-start mb-2">
                  <div>
                    <p class="font-black text-sm uppercase">${p.name}</p>
                    <p class="text-[9px] text-slate-400 font-bold uppercase">${p.service || ''} · ${b ? b.n : 'N/A'}</p>
                  </div>
                  <span class="font-black text-emerald-700 text-sm">${fmt(p.precioFinal)}</span>
                </div>
                <button onclick="app.procesarPendiente(${i})"
                  class="w-full bg-amber-500 hover:bg-amber-600 text-white py-2 rounded-xl text-[9px] font-black uppercase transition-all">
                  <i class="fas fa-cash-register mr-1"></i>Cobrar
                </button>
              </div>`;
          }).join('');
        }
      }

      // — Sección destacada en t-atencion (panel principal admin) —
      const porSec  = document.getElementById('porCobrarSection');
      const porList = document.getElementById('porCobrarList');
      const porCnt  = document.getElementById('porCobrarCnt');
      if (porSec) {
        if (!pend.length) { porSec.classList.add('hidden'); }
        else {
          porSec.classList.remove('hidden');
          porCnt.textContent = pend.length;
          porList.innerHTML = pend.map((p, i) => {
            const b = _data.barberos.find(x => x.id === p.barberoId);
            return `
              <div class="card-pendiente-pago p-4 rounded-2xl text-center">
                <div class="mb-2"><span class="badge-por-pagar">💵 Por Pagar en Caja</span></div>
                <p class="text-[9px] font-black text-amber-600 uppercase mb-1">${b ? b.n : 'N/A'}</p>
                <h4 class="font-black text-slate-800 uppercase text-base mb-1">${p.name}</h4>
                <p class="text-[8px] text-slate-500 uppercase mb-2">${p.service || ''}</p>
                <p class="font-black text-xl text-amber-700 mb-3">${fmt(p.precioFinal)}</p>
                <button onclick="app.procesarPendiente(${i})"
                  class="w-full bg-amber-500 hover:bg-amber-600 text-white py-2 rounded-xl text-[9px] font-black uppercase transition-all">
                  <i class="fas fa-cash-register mr-1"></i>Cobrar Ahora
                </button>
              </div>`;
          }).join('');
        }
      }

      // — Sección en t-cajero —
      const cjSec  = document.getElementById('cjPendienteSection');
      const cjList = document.getElementById('cjPendienteList');
      const cjCnt  = document.getElementById('cjPendienteCnt');
      if (cjSec) {
        if (!pend.length) { cjSec.classList.add('hidden'); }
        else {
          cjSec.classList.remove('hidden');
          cjCnt.textContent = pend.length;
          cjList.innerHTML = pend.map((p, i) => {
            const b = _data.barberos.find(x => x.id === p.barberoId);
            return `
              <div class="card-pendiente-pago p-4 rounded-2xl text-center">
                <div class="mb-2"><span class="badge-por-pagar">💵 Por Pagar</span></div>
                <p class="text-[9px] font-black text-amber-600 uppercase mb-1">${b ? b.n : 'N/A'}</p>
                <h4 class="font-black text-slate-800 uppercase text-base mb-1">${p.name}</h4>
                <p class="font-black text-xl text-amber-700 mb-3">${fmt(p.precioFinal)}</p>
                <button onclick="app.procesarPendiente(${i})"
                  class="w-full bg-amber-500 hover:bg-amber-600 text-white py-2 rounded-xl text-[9px] font-black uppercase transition-all">
                  <i class="fas fa-cash-register mr-1"></i>Cobrar
                </button>
              </div>`;
          }).join('');
        }
      }
    },

    procesarPendiente(idx) {
      _tmpPend = idx;
      const p  = _data.pendienteCaja[idx];
      if (!p) return;
      const b  = _data.barberos.find(x => x.id === p.barberoId);
      document.getElementById('ppTitle').textContent  = p.name;
      document.getElementById('ppBarber').textContent = `Atendido por: ${b ? b.n : 'N/A'} · ${p.service || ''}`;
      document.getElementById('ppVal').value          = p.precioFinal;
      _pub.openM('mProcesarPendiente');
    },

    async confirmarPendiente() {
      if (_tmpPend === null) return;
      const item   = _data.pendienteCaja.splice(_tmpPend, 1)[0];
      const price  = parseInt(document.getElementById('ppVal').value) || item.precioFinal;
      const metodo = document.getElementById('ppMetodo').value;
      const final  = { ...item, price, method: metodo, timestamp: new Date().toISOString(),
                       _cobradoPor: _currentUser ? _currentUser.id : null };
      _data.hoy.push(final);
      _tmpPend = null;
      _pub.imprimirTicketVenta(final);
      _pub.closeM();
      await _pub.save();
      _logAudit('pago_pendiente_cobrado', { cliente:final.name, monto:price, metodo, barbero:final.barber||'' });
      _pub.renderCaja(); _pub.renderPendiente(); _pub.render();
      _pub._toast('Pago registrado ✓', '#16a34a');
    },

    // ──── §10.6 REGISTRO Y COLA ───────────────────────────────
    reg() {
      const n = document.getElementById('inN').value.trim();
      const p = document.getElementById('inP').value;
      const t = document.getElementById('inTarget').value;
      if (!n || !p) return;

      const ocupados = _data.activos.map(a => a.barber);
      const pausa    = _data.pausa || [];
      const cliente  = { name: n, price: parseInt(p), service: document.getElementById('inS').value, target: t, startTime: Date.now() };
      let asignado   = false;

      if (t !== 'S/A') {
        if (!ocupados.includes(t) && !pausa.includes(t) && _data.turnos.includes(t)) {
          const bObj = _data.barberos.find(b => b.n === t);
          _data.activos.push({ ...cliente, barber: t, barberoId: bObj?.id || null });
          asignado = true;
        }
      } else {
        const libre = _data.turnos.find(b => !ocupados.includes(b) && !pausa.includes(b));
        if (libre) {
          const bObj = _data.barberos.find(b => b.n === libre);
          _data.activos.push({ ...cliente, barber: libre, barberoId: bObj?.id || null });
          asignado = true;
        }
      }

      if (!asignado) {
        _data.espera.push(cliente);
        _pub._toast('Todos ocupados — cliente en cola de espera', '#f59e0b');
      }

      document.getElementById('inN').value = '';
      document.getElementById('inP').value = '';
      _pub.save(); _pub.render();
    },

    next() {
      if (!_data.espera.length) return alert('No hay clientes en espera.');
      const ocupados = _data.activos.map(a => a.barber), pausa = _data.pausa || [];
      const ip = _data.espera.findIndex(c => c.target !== 'S/A' && !ocupados.includes(c.target) && !pausa.includes(c.target) && _data.turnos.includes(c.target));
      if (ip !== -1) {
        const c = _data.espera.splice(ip, 1)[0];
        const bObj = _data.barberos.find(b => b.n === c.target);
        _data.activos.push({ ...c, barber: c.target, barberoId: bObj?.id || null, startTime: Date.now() });
      } else {
        const il    = _data.espera.findIndex(c => c.target === 'S/A');
        const libre = _data.turnos.find(b => !ocupados.includes(b) && !pausa.includes(b));
        if (il !== -1 && libre) {
          const c = _data.espera.splice(il, 1)[0];
          const bObj = _data.barberos.find(b => b.n === libre);
          _data.activos.push({ ...c, barber: libre, barberoId: bObj?.id || null, startTime: Date.now() });
        } else return alert('Todos los profesionales están ocupados.');
      }
      _pub.save(); _pub.render();
    },

    openChange(i) {
      _tmpRA = i;
      const c = _data.espera[i];
      document.getElementById('raClienteName').textContent = c.name;
      document.getElementById('raSelect').innerHTML =
        '<option value="S/A">CUALQUIER PROFESIONAL</option>' +
        _data.barberos.map(b => `<option value="${b.n}" ${b.n === c.target ? 'selected' : ''}>${b.n}</option>`).join('');
      _pub.openM('mReAsignar');
    },
    confirmReAsignar() {
      if (_tmpRA === null) return;
      _data.espera[_tmpRA].target = document.getElementById('raSelect').value;
      _tmpRA = null; _pub.closeM(); _pub.save(); _pub.render();
    },

    // ──── §10.7 REPOSO ────────────────────────────────────────
    ponerEnReposo(i) {
      const c = _data.activos[i];
      _data.reposo.push({ ...c, tiempoAcum: Date.now() - c.startTime, reposoDesde: Date.now() });
      _data.activos.splice(i, 1);
      _data.turnos = [..._data.turnos.filter(t => t !== c.barber), c.barber];
      _pub._toast(`${c.name} en reposo — ${c.barber} liberado`, '#8b5cf6');
      _pub.save(); _pub.render();
    },

    openRetomar(i) {
      _tmpRT = i;
      const c       = _data.reposo[i];
      const ocupados = _data.activos.map(a => a.barber), pausa = _data.pausa || [];
      const libres  = _data.turnos.filter(b => !ocupados.includes(b) && !pausa.includes(b));
      document.getElementById('rtClienteName').textContent = `${c.name} · ${c.service || ''}`;
      document.getElementById('rtBarberSelect').innerHTML =
        (libres.length ? libres : _data.barberos.map(b => b.n))
          .map(b => `<option value="${b}" ${b === c.barber ? 'selected' : ''}>${b}</option>`).join('');
      _pub.openM('mRetomar');
    },

    confirmRetomar() {
      if (_tmpRT === null) return;
      const c  = _data.reposo[_tmpRT];
      const nb = document.getElementById('rtBarberSelect').value;
      _data.activos.push({ ...c, barber: nb, startTime: Date.now() - c.tiempoAcum });
      _data.reposo.splice(_tmpRT, 1);
      _tmpRT = null; _pub.closeM(); _pub.save(); _pub.render();
    },

    // ──── §10.8 PAGOS (admin desde activos) ──────────────────
    prepP(i) {
      _tmpI = i;
      const a = _data.activos[i];
      document.getElementById('pTitle').textContent = a.name;
      document.getElementById('pVal').value         = a.price;
      document.getElementById('pBarber').innerHTML  =
        _data.barberos.map(b => `<option value="${b.n}" ${b.n === a.barber ? 'selected' : ''}>${b.n}</option>`).join('');
      _pub.openM('mPago');
    },

    async pay() {
      const itm    = _data.activos.splice(_tmpI, 1)[0];
      const barber = document.getElementById('pBarber').value;
      const precio = parseInt(document.getElementById('pVal').value);
      const metodo = document.getElementById('pMetodo').value;
      const bObj   = _data.barberos.find(b => b.n === barber);
      const final  = { ...itm, price: precio, barber, method: metodo,
                       timestamp: new Date().toISOString(),
                       barberoId: bObj ? bObj.id : (itm.barberoId || null),
                       _cobradoPor: _currentUser ? _currentUser.id : null };
      _data.hoy.push(final);
      _data.turnos = [..._data.turnos.filter(t => t !== barber), barber];
      _pub.imprimirTicketVenta(final);
      _pub.closeM();
      await _pub.save();
      _logAudit('pago_registrado', { cliente:final.name, servicio:final.service||'', monto:precio, metodo, barbero:barber });
      _pub.render(); _pub.renderCaja();
    },

    // ──── §10.9 RENDER PRINCIPAL ──────────────────────────────
    render() {
      const turnos  = _data.turnos  || [];
      const ocupados = _data.activos.map(a => a.barber);
      const pausa   = _data.pausa   || [];
      const reposo  = _data.reposo  || [];

      // Ayudante: mini avatar
      const avMini = (bName, sz = 28) => {
        const b = _data.barberos.find(x => x.n === bName);
        return b && b.photo
          ? `<img src="${b.photo}" style="width:${sz}px;height:${sz}px;border-radius:50%;object-fit:cover;flex-shrink:0;">`
          : `<div style="width:${sz}px;height:${sz}px;border-radius:50%;background:#f1f5f9;display:flex;align-items:center;justify-content:center;font-weight:900;font-size:${Math.round(sz*.4)}px;color:#94a3b8;flex-shrink:0;">${bName.charAt(0)}</div>`;
      };

      // ── Config: lista de barberos ──
      document.getElementById('bList').innerHTML = _data.barberos.map((b, i) => {
        const av = b.photo
          ? `<img src="${b.photo}" class="av48">`
          : `<div class="av-ph">${b.n.charAt(0)}</div>`;
        return `<div class="flex items-center gap-3 py-2 px-3 bg-slate-50 rounded-xl">
          ${av}
          <div class="flex-1 min-w-0">
            <div class="font-black text-xs uppercase truncate">${b.n}</div>
            <div class="text-[9px] text-emerald-600 font-bold">${b.c}% comisión</div>
          </div>
          <button onclick="app.rmBarber(${i})" class="text-red-300 hover:text-red-500 ml-2 text-xs"><i class="fas fa-trash"></i></button>
        </div>`;
      }).join('');

      document.getElementById('sList').innerHTML = _data.servicios.map((s, i) =>
        `<div class="flex justify-between text-xs py-2 px-4 bg-slate-50 rounded-xl font-black uppercase">
          <span>${s.n} (${fmt(s.p)})</span>
          <button onclick="app.rmServicio(${i})" class="text-red-300 hover:text-red-500"><i class="fas fa-trash"></i></button>
        </div>`).join('');

      // ── Disponibles (fuera de turno) ──
      document.getElementById('entryB').innerHTML = _data.barberos
        .filter(b => !turnos.includes(b.n))
        .map(b => `
          <button onclick="app.inB('${b.n}')"
            class="bg-emerald-50 hover:bg-emerald-600 hover:text-white text-emerald-800 p-3 rounded-xl text-[10px] font-black uppercase transition-all flex items-center gap-2">
            ${avMini(b.n)}
            <span class="flex-1 text-left">${b.n}</span>
            <i class="fas fa-plus-circle"></i>
          </button>`).join('');

      // ── Fila de turnos ──
      document.getElementById('listB').innerHTML = turnos.map(n => {
        const isBusy  = ocupados.includes(n);
        const isPausa = pausa.includes(n);
        const cls     = isBusy ? 'barber-busy' : isPausa ? 'barber-pausa' : 'barber-libre';
        return `<div class="p-3 border rounded-xl text-[11px] font-black flex items-center gap-2 ${cls} uppercase shadow-sm">
          ${avMini(n)}
          <span class="flex-1">${n}</span>
          <div class="flex gap-2 items-center">
            ${!isBusy
              ? `<button onclick="app.togglePausa('${n}')" class="text-slate-400 hover:text-amber-500 text-xs"><i class="fas ${isPausa ? 'fa-play' : 'fa-pause'}"></i></button>`
              : '<i class="fas fa-cut text-red-400 animate-pulse text-xs"></i>'}
            <button onclick="app.outB('${n}')" class="text-slate-300 hover:text-red-500 text-xs"><i class="fas fa-times-circle"></i></button>
          </div>
        </div>`;
      }).join('');

      // ── Próximo barbero ──
      const proxEl = document.getElementById('proximoBarber');
      const libre  = turnos.find(b => !ocupados.includes(b) && !pausa.includes(b));
      if (libre) {
        const bObj = _data.barberos.find(x => x.n === libre);
        const avG  = bObj?.photo
          ? `<img src="${bObj.photo}" style="width:52px;height:52px;border-radius:50%;object-fit:cover;border:3px solid rgba(255,255,255,.6);margin:0 auto 6px;display:block;">`
          : `<div style="width:52px;height:52px;border-radius:50%;background:rgba(255,255,255,.2);display:flex;align-items:center;justify-content:center;font-size:1.4rem;font-weight:900;margin:0 auto 6px;">${libre.charAt(0)}</div>`;
        proxEl.innerHTML = `
          <div class="proximo-glow w-full px-4 py-3 rounded-xl text-center relative">
            ${avG}
            <div style="font-size:8px;font-weight:900;opacity:.8;text-transform:uppercase;letter-spacing:.15em;margin-bottom:2px;">Próximo</div>
            <div style="font-size:15px;font-weight:900;text-transform:uppercase;">${libre}</div>
            <div style="font-size:8px;opacity:.7;margin-top:3px;"><i class="fas fa-circle" style="font-size:6px;margin-right:4px;"></i>Disponible</div>
          </div>`;
      } else if (turnos.length) {
        let mt = null, tMin = Infinity;
        _data.activos.forEach(a => { if (a.startTime < tMin) { tMin = a.startTime; mt = a.barber; } });
        proxEl.innerHTML = `
          <div class="w-full px-4 py-3 rounded-xl bg-amber-50 border-2 border-amber-200 text-center">
            <div style="font-size:8px;font-weight:900;color:#d97706;text-transform:uppercase;margin-bottom:4px;">Todos Ocupados</div>
            <div style="font-size:15px;font-weight:900;color:#92400e;text-transform:uppercase;">${mt || '—'}</div>
            <div style="font-size:8px;color:#d97706;margin-top:3px;"><i class="fas fa-clock" style="margin-right:4px;"></i>Cliente más antiguo</div>
          </div>`;
      } else {
        proxEl.innerHTML = `<span class="text-slate-300 text-[10px] font-black uppercase">Sin barberos en turno</span>`;
      }

      // ── Sillas activas (admin view) ──
      document.getElementById('sillas').innerHTML = _data.activos.map((a, i) => {
        const bObj = _data.barberos.find(x => x.n === a.barber);
        const avG  = bObj?.photo
          ? `<img src="${bObj.photo}" class="av64 mx-auto mb-2">`
          : `<div class="av-ph mx-auto mb-2" style="width:56px;height:56px;font-size:1.3rem;">${a.barber.charAt(0)}</div>`;
        return `
          <div class="bg-white p-5 rounded-3xl border border-slate-100 text-center shadow-lg">
            ${avG}
            <p class="text-[9px] font-black text-emerald-600 uppercase mb-1">${a.barber}</p>
            <h4 class="font-black text-slate-800 uppercase text-lg mb-1">${a.name}</h4>
            <p class="text-[8px] text-slate-400 uppercase mb-2">${a.service || ''}</p>
            <div class="timer mb-4" id="timer-${i}">00:00</div>
            <div class="flex gap-2">
              <button onclick="app.ponerEnReposo(${i})"
                class="flex-1 bg-purple-50 hover:bg-purple-500 hover:text-white text-purple-600 py-2 rounded-xl text-[9px] font-black uppercase border border-purple-100 transition-all">
                <i class="fas fa-couch mr-1"></i>Reposo
              </button>
              <button onclick="app.prepP(${i})"
                class="flex-1 bg-slate-900 text-white py-2 rounded-xl text-[9px] font-black uppercase hover:bg-emerald-600 transition-all">
                <i class="fas fa-check mr-1"></i>Cobrar
              </button>
            </div>
          </div>`;
      }).join('');

      // ── Reposo ──
      const reposoSec = document.getElementById('reposoSection');
      if (reposo.length) {
        reposoSec.classList.remove('hidden');
        document.getElementById('reposoCnt').textContent = reposo.length;
        document.getElementById('reposoGrid').innerHTML = reposo.map((r, i) => `
          <div class="bg-white p-5 rounded-3xl border reposo-card text-center shadow-md">
            <span class="badge-reposo inline-block mb-2"><i class="fas fa-couch mr-1"></i>EN REPOSO</span>
            <p class="text-[9px] font-black text-purple-500 uppercase mb-1">${r.barber}</p>
            <h4 class="font-black text-slate-800 uppercase text-lg mb-1">${r.name}</h4>
            <p class="text-[8px] text-slate-400 uppercase mb-2">${r.service || ''}</p>
            <div class="timer timer-purple mb-4" id="timer-reposo-${i}">00:00</div>
            <div class="flex gap-2">
              <button onclick="app.rmReposo(${i})"
                class="flex-1 bg-red-50 hover:bg-red-500 hover:text-white text-red-400 py-2 rounded-xl text-[9px] font-black uppercase border border-red-100 transition-all">
                <i class="fas fa-times mr-1"></i>Cancelar
              </button>
              <button onclick="app.openRetomar(${i})"
                class="flex-1 bg-purple-600 hover:bg-purple-700 text-white py-2 rounded-xl text-[9px] font-black uppercase transition-all">
                <i class="fas fa-play mr-1"></i>Retomar
              </button>
            </div>
          </div>`).join('');
      } else reposoSec.classList.add('hidden');

      // ── Cola de espera ──
      document.getElementById('cola').innerHTML = _data.espera.map((c, i) => `
        <div class="p-4 bg-white border border-slate-100 rounded-2xl shadow-sm">
          <div class="flex justify-between items-start mb-2">
            <div>
              <b class="text-[12px] uppercase">${c.name}</b><br>
              <small class="text-[8px] font-black text-emerald-600">
                ${c.target === 'S/A' ? 'ORDEN DE TURNO' : 'SOLICITA: ' + c.target}
              </small>
            </div>
            <button onclick="app.rmEspera(${i})" class="text-red-200 hover:text-red-500 text-xs"><i class="fas fa-minus-circle"></i></button>
          </div>
          <button onclick="app.openChange(${i})"
            class="w-full bg-slate-50 hover:bg-slate-100 text-[8px] font-black py-2 rounded-xl border-dashed border-2 uppercase text-slate-400">
            <i class="fas fa-random mr-1"></i>Re-Asignar
          </button>
        </div>`).join('');

      document.getElementById('waitCnt').textContent = _data.espera.length;

      // Selects de recepción
      document.getElementById('inS').innerHTML = '<option value="">Seleccionar Servicio...</option>' +
        _data.servicios.map(s => `<option value="${s.n}">${s.n}</option>`).join('');
      document.getElementById('inTarget').innerHTML = '<option value="S/A">CUALQUIER PROFESIONAL</option>' +
        _data.barberos.map(b => `<option value="${b.n}">PEDIR A: ${b.n.toUpperCase()}</option>`).join('');

      // Refrescar clientes por cobrar en el panel
      _pub.renderPendiente();
    },

    // ──── §10.10 TIMERS ──────────────────────────────────────
    updateTimers() {
      _data.activos.forEach((a, i) => {
        const el = document.getElementById(`timer-${i}`);
        if (el) { const d = Math.floor((Date.now() - a.startTime) / 1000); el.textContent = `${Math.floor(d/60)}:${String(d%60).padStart(2,'0')}`; }
      });
      (_data.reposo || []).forEach((r, i) => {
        const el = document.getElementById(`timer-reposo-${i}`);
        if (el) { const d = Math.floor(r.tiempoAcum / 1000); el.textContent = `${Math.floor(d/60)}:${String(d%60).padStart(2,'0')}`; }
      });
    },

    // ──── §10.11 CAJA ─────────────────────────────────────────
    renderCaja() {
      const h    = _data.hoy || [];
      const vEf  = h.filter(m => m.method === 'EFECTIVO'      && !m.type).reduce((a,b) => a+b.price, 0);
      const gas  = h.filter(m => m.type   === 'GASTO').reduce((a,b) => a+b.price, 0);
      const vTar = h.filter(m => m.method === 'TARJETA'       && !m.type).reduce((a,b) => a+b.price, 0);
      const vTra = h.filter(m => m.method === 'TRANSFERENCIA' && !m.type).reduce((a,b) => a+b.price, 0);
      const vTot = h.filter(m => !m.type).reduce((a,b) => a+b.price, 0);

      document.getElementById('totalEfec').textContent  = fmt(vEf - gas);
      document.getElementById('totalTar').textContent   = fmt(vTar);
      document.getElementById('totalTrans').textContent = fmt(vTra);
      document.getElementById('totalVenta').textContent = fmt(vTot);

      document.getElementById('movs').innerHTML = h.map(m => `
        <div class="flex justify-between py-3 text-[10px] uppercase font-black">
          <div>${m.name}<br><span class="text-slate-400 text-[8px]">${m.method || 'CAJA'} · ${m.barber || 'S/A'}</span></div>
          <span class="${m.type ? 'text-red-500' : 'text-emerald-600'}">${m.type ? '-' : ''}${fmt(m.price)}</span>
        </div>`).reverse().join('');

      _pub.renderPendiente();
      _pub.verHistorialCierre();
    },

    calcDiff() {
      const h   = _data.hoy || [];
      const sEf  = h.filter(m => m.method === 'EFECTIVO'      && !m.type).reduce((a,b) => a+b.price,0) - h.filter(m => m.type === 'GASTO').reduce((a,b) => a+b.price,0);
      const sTar = h.filter(m => m.method === 'TARJETA'       && !m.type).reduce((a,b) => a+b.price,0);
      const sTra = h.filter(m => m.method === 'TRANSFERENCIA' && !m.type).reduce((a,b) => a+b.price,0);
      const rEf  = parseInt(document.getElementById('checkEf').value)    || 0;
      const rTar = parseInt(document.getElementById('checkTar').value)   || 0;
      const rTra = parseInt(document.getElementById('checkTrans').value) || 0;

      const difCls = d => d < 0 ? 'diff-neg' : d > 0 ? 'diff-pos' : 'diff-zero';
      const rows   = [['💵 Efectivo',sEf,rEf],['💳 Tarjeta',sTar,rTar],['📱 Transferencia',sTra,rTra]];
      document.getElementById('auditTable').innerHTML = rows.map(([l,s,r]) => {
        const d = r - s;
        return `<tr><td class="p-3 font-black text-[11px]">${l}</td>
          <td class="p-3 text-right font-bold text-slate-600">${fmt(s)}</td>
          <td class="p-3 text-right font-bold text-slate-900">${fmt(r)}</td>
          <td class="p-3 text-right font-black text-[11px] ${difCls(d)}">${fmtDiff(d)}</td></tr>`;
      }).join('');

      const totS = sEf+sTar+sTra, totR = rEf+rTar+rTra, totD = totR - totS;
      document.getElementById('auditFoot').innerHTML =
        `<tr><td class="p-3 font-black text-[11px] uppercase">TOTAL</td>
         <td class="p-3 text-right font-black text-emerald-700">${fmt(totS)}</td>
         <td class="p-3 text-right font-black text-slate-900">${fmt(totR)}</td>
         <td class="p-3 text-right font-black ${difCls(totD)}">${fmtDiff(totD)}</td></tr>`;

      document.getElementById('auditBarbers').innerHTML = _data.barberos.map(b => {
        const mv  = h.filter(v => v.barber === b.n && !v.type);
        if (!mv.length) return '';
        const ef  = mv.filter(v => v.method === 'EFECTIVO'     ).reduce((a,c) => a+c.price,0);
        const tar = mv.filter(v => v.method === 'TARJETA'      ).reduce((a,c) => a+c.price,0);
        const tra = mv.filter(v => v.method === 'TRANSFERENCIA').reduce((a,c) => a+c.price,0);
        const av  = b.photo
          ? `<img src="${b.photo}" style="width:36px;height:36px;border-radius:50%;object-fit:cover;flex-shrink:0;">`
          : `<div style="width:36px;height:36px;border-radius:50%;background:#f1f5f9;display:flex;align-items:center;justify-content:center;font-weight:900;font-size:14px;color:#94a3b8;flex-shrink:0;">${b.n.charAt(0)}</div>`;
        return `<div style="display:flex;align-items:center;gap:10px;background:#f8fafc;border-radius:14px;padding:10px 14px;border:1px solid #e2e8f0;">
          ${av}
          <div style="flex:1;min-width:0;">
            <div style="font-weight:900;font-size:11px;text-transform:uppercase;">${b.n} · ${mv.length} serv.</div>
            <div style="font-size:9px;color:#64748b;font-weight:700;margin-top:2px;">💵${fmt(ef)} 💳${fmt(tar)} 📱${fmt(tra)}</div>
          </div>
          <div style="font-weight:900;font-size:14px;color:#16a34a;">${fmt(ef+tar+tra)}</div>
        </div>`;
      }).join('');
    },

    buscarCierre() {
      const fecha = document.getElementById('searchDate').value; if (!fecha) return;
      const filtrado = (_data.historial||[]).filter(c => c.fullFecha === fecha);
      document.getElementById('historialCierres').innerHTML = filtrado.length
        ? filtrado.map((c,i) => `<div class="p-4 border rounded-2xl bg-slate-50 text-[10px] uppercase font-black">
            <div class="flex justify-between border-b pb-2 mb-2 text-slate-500">
              <span>${c.fecha}</span>
              <button onclick="app.reimprimir(${i})" class="text-emerald-600 underline text-[9px]">Ver Ticket</button>
            </div>
            <div class="flex justify-between flex-wrap gap-1">
              <span class="text-emerald-700">SIS: ${fmt(c.sis?.tot||0)}</span>
              <span>REAL: ${fmt(c.real.tot)}</span>
              <span class="${c.dif.ef<0?'text-red-500':'text-emerald-600'}">ΔEF: ${fmtDiff(c.dif.ef)}</span>
            </div>
          </div>`).join('')
        : '<p class="text-slate-300 text-[10px] font-black uppercase text-center py-4">Sin cierres esa fecha</p>';
    },

    openM(id) {
      document.getElementById(id).classList.remove('hidden');
      document.getElementById(id).classList.add('flex');
      if (id === 'mCierreCheck') _pub.calcDiff();
    },
    closeM() {
      document.querySelectorAll('.fixed').forEach(m => {
        m.classList.add('hidden'); m.classList.remove('flex');
      });
    },

    async confirmarCierre() {
      const h = _data.hoy || []; if (!h.length) return alert('No hay movimientos hoy.');
      const rEf  = parseInt(document.getElementById('checkEf').value)    || 0;
      const rTar = parseInt(document.getElementById('checkTar').value)   || 0;
      const rTra = parseInt(document.getElementById('checkTrans').value) || 0;
      const sEf  = h.filter(m=>m.method==='EFECTIVO'      &&!m.type).reduce((a,b)=>a+b.price,0)-h.filter(m=>m.type==='GASTO').reduce((a,b)=>a+b.price,0);
      const sTar = h.filter(m=>m.method==='TARJETA'       &&!m.type).reduce((a,b)=>a+b.price,0);
      const sTra = h.filter(m=>m.method==='TRANSFERENCIA' &&!m.type).reduce((a,b)=>a+b.price,0);

      const perBarber = _data.barberos.map(b => {
        const mv  = h.filter(v=>v.barber===b.n&&!v.type);
        const ef  = mv.filter(v=>v.method==='EFECTIVO'     ).reduce((a,c)=>a+c.price,0);
        const tar = mv.filter(v=>v.method==='TARJETA'      ).reduce((a,c)=>a+c.price,0);
        const tra = mv.filter(v=>v.method==='TRANSFERENCIA').reduce((a,c)=>a+c.price,0);
        return { nombre:b.n, c:b.c, cant:mv.length, ef, tar, tra, total:ef+tar+tra };
      }).filter(r=>r.total>0);

      const cierre = {
        fecha: new Date().toLocaleDateString('es-CL'),
        fullFecha: new Date().toISOString().split('T')[0],
        detalle: [...h], perBarber,
        sis:  {ef:sEf,tar:sTar,tra:sTra,tot:sEf+sTar+sTra},
        real: {ef:rEf,tar:rTar,tra:rTra,tot:rEf+rTar+rTra},
        dif:  {ef:rEf-sEf,tar:rTar-sTar,tra:rTra-sTra}
      };
      _data.historial.push(cierre);
      // Guardar también en subcolección independiente para histórico permanente
      try {
        await db.collection(_FS_HIST).add({
          ...cierre, _cierradoPor: _currentUser ? _currentUser.id : null,
          _serverTs: firebase.firestore.FieldValue.serverTimestamp()
        });
      } catch(e) { console.warn('[CIERRE] subcolección:', e.message); }
      _logAudit('cierre_de_caja', { fecha:cierre.fullFecha, totalSistema:cierre.sis.tot,
        totalReal:cierre.real.tot, diferencia:cierre.real.tot - cierre.sis.tot });
      _pub.imprimirTicketCierre(cierre);
      _data.hoy = [];
      await _pub.save();
      _pub.render(); _pub.renderCaja(); _pub.verHistorialCierre(); _pub.closeM();
    },

    verHistorialCierre() {
      const h = _data.historial || [];
      document.getElementById('historialCierres').innerHTML = [...h].reverse().map((c,i) => `
        <div class="p-4 border rounded-2xl bg-slate-50 text-[10px] uppercase font-black">
          <div class="flex justify-between border-b pb-2 mb-2 text-slate-500">
            <span>${c.fecha}</span>
            <button onclick="app.reimprimir(${h.length-1-i})" class="text-emerald-600 underline text-[9px]">Ver Ticket</button>
          </div>
          <div class="flex justify-between flex-wrap gap-1">
            <span class="text-emerald-700">SIS: ${fmt(c.sis?.tot||0)}</span>
            <span>REAL: ${fmt(c.real.tot)}</span>
            <span class="${c.dif.ef<0?'text-red-500':'text-emerald-600'}">ΔEF: ${fmtDiff(c.dif.ef)}</span>
          </div>
        </div>`).join('');
    },

    reimprimir(i) { _pub.imprimirTicketCierre(_data.historial[i]); },

    regGasto() {
      const d = document.getElementById('gd').value.trim();
      const p = parseInt(document.getElementById('ga').value);
      if (d && p) {
        _data.hoy.push({ type:'GASTO', name:d, price:p, method:'EFECTIVO', timestamp:new Date().toISOString() });
        _pub.closeM(); _pub.save(); _pub.renderCaja();
        document.getElementById('gd').value=''; document.getElementById('ga').value='';
      }
    },

    // ──── §10.12 STAFF / COMISIONES ──────────────────────────
    renderStaff() {
      const desde = document.getElementById('fechaDesde').value;
      const hasta = document.getElementById('fechaHasta').value;
      if (!desde || !hasta) return alert('Seleccione rango de fechas.');
      const d = new Date(desde + 'T00:00:00'), h = new Date(hasta + 'T23:59:59');
      let todas = [...(_data.hoy||[])];
      (_data.historial||[]).forEach(c => { if(c.detalle) todas = [...todas,...c.detalle]; });
      const filtradas = todas.filter(v => { const fv=new Date(v.timestamp); return fv>=d&&fv<=h&&!v.type; });

      document.getElementById('panelStaff').innerHTML = _data.barberos.map(b => {
        const cortes = filtradas.filter(v=>v.barber===b.n);
        const bruto  = cortes.reduce((a,c)=>a+c.price,0);
        const pago   = Math.round(bruto*(b.c/100));
        const av     = b.photo
          ? `<img src="${b.photo}" style="width:56px;height:56px;border-radius:50%;object-fit:cover;border:3px solid #16a34a;margin:0 auto 8px;display:block;">`
          : `<div style="width:56px;height:56px;border-radius:50%;background:#f0fdf4;display:flex;align-items:center;justify-content:center;font-size:1.4rem;font-weight:900;color:#16a34a;margin:0 auto 8px;border:3px solid #16a34a;">${b.n.charAt(0)}</div>`;
        return `<div class="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm text-center">
          ${av}
          <div class="flex justify-between font-black text-xs uppercase mb-3"><span>${b.n}</span><span class="text-emerald-600">${cortes.length} SERV.</span></div>
          <div class="bg-slate-900 p-4 rounded-2xl text-emerald-400 font-black text-xl flex justify-between items-center mb-4">
            <span class="text-[9px] text-slate-500 uppercase">Comisión ${b.c}%</span>${fmt(pago)}
          </div>
          <button onclick="app.imprimirPagoStaff('${b.n}',${cortes.length},${pago},'${desde}','${hasta}')"
            class="w-full border-2 border-slate-900 py-3 rounded-xl text-[10px] font-black uppercase hover:bg-slate-900 hover:text-white transition-all">
            Imprimir Comprobante
          </button>
        </div>`;
      }).join('');
    },

    // ──── §10.13 CONFIG ───────────────────────────────────────
    async addB() {
      const n    = document.getElementById('nb').value.trim();
      const c    = parseInt(document.getElementById('nc').value) || 50;
      const usr  = document.getElementById('nb_user').value.trim().toLowerCase();
      const pass = document.getElementById('nb_pass').value;

      if (!n)          return _pub._toast('El nombre del profesional es requerido', '#ef4444');
      if (!usr||!pass) return _pub._toast('El usuario y contraseña son obligatorios', '#ef4444');
      if (_TRAPS.includes(pass.toLowerCase())) return _pub._toast('Contraseña no permitida (muy débil)', '#ef4444');
      if (_data.usuarios.find(u => u.username === usr)) return _pub._toast('Ese nombre de usuario ya existe', '#ef4444');

      const bId  = 'b_' + Date.now();
      const uId  = 'u_' + (Date.now() + 1);
      const hash = await _sha256(pass);

      // Crear barbero vinculado a usuario
      _data.barberos.push({ id: bId, n, c, photo: _photoB64 || '', userId: uId });

      // Crear cuenta de acceso con rol barbero
      _data.usuarios.push({
        id: uId, nombre: n, username: usr, hash,
        rol: 'barbero', barberoId: bId, activo: true
      });

      // Limpiar formulario
      document.getElementById('nb').value   = '';
      document.getElementById('nb_user').value = '';
      document.getElementById('nb_pass').value = '';
      _photoB64 = '';
      const prev = document.getElementById('photoPreview');
      prev.src = ''; prev.classList.add('hidden');
      document.getElementById('photoPH').classList.remove('hidden');
      document.getElementById('photoInput').value = '';

      _pub.save(); _pub.render(); _pub.renderAdmin();
      _pub._toast(`✓ ${n} agregado — login: @${usr}`, '#16a34a');
    },

    addS() {
      const n = document.getElementById('ns').value.trim(), p = parseInt(document.getElementById('nsp').value);
      if (n && p) {
        _data.servicios.push({n, p});
        document.getElementById('ns').value=''; document.getElementById('nsp').value='';
        _pub.save(); _pub.render();
      }
    },

    rmBarber(i) {
      const b = _data.barberos[i];
      // Eliminar usuario vinculado también
      if (b.userId) _data.usuarios = _data.usuarios.filter(u => u.id !== b.userId);
      _data.barberos.splice(i, 1);
      _pub.save(); _pub.render(); _pub.renderAdmin();
    },
    rmServicio(i) { _data.servicios.splice(i,1);  _pub.save(); _pub.render(); },
    rmEspera(i)   { _data.espera.splice(i,1);     _pub.save(); _pub.render(); },
    rmReposo(i)   { _data.reposo.splice(i,1);     _pub.save(); _pub.render(); },

    inB(n)   { if (!_data.turnos.includes(n)) _data.turnos.push(n); _pub.save(); _pub.render(); },
    outB(n)  { _data.turnos = _data.turnos.filter(t => t !== n); _pub.save(); _pub.render(); },
    togglePausa(n) {
      _data.pausa = _data.pausa.includes(n) ? _data.pausa.filter(p => p !== n) : [..._data.pausa, n];
      _pub.save(); _pub.render();
    },
    price() {
      const s = _data.servicios.find(x => x.n === document.getElementById('inS').value);
      if (s) document.getElementById('inP').value = s.p;
    },
    previewPhoto(input) {
      const file = input.files[0]; if (!file) return;
      const reader = new FileReader();
      reader.onload = e => {
        _photoB64 = e.target.result;
        const prev = document.getElementById('photoPreview');
        prev.src = _photoB64; prev.classList.remove('hidden');
        document.getElementById('photoPH').classList.add('hidden');
      };
      reader.readAsDataURL(file);
    },

    // ──── §10.14 IMPRESIÓN ────────────────────────────────────
    /* ── CSS térmico inyectado en ventanas de impresión ──────────────────
       Optimizado para tiqueteras de 80 mm (área útil ~72 mm).
       Sin sombras, gradientes ni fondos oscuros (ahorra cabezal térmico).
       Fuente monospace para alineación precisa de números.
    ──────────────────────────────────────────────────────────────────── */
    _css: `
      @page { size: 80mm auto; margin: 0; }

      * { box-sizing: border-box; margin: 0; padding: 0; }

      body {
        font-family: 'Courier New', Courier, monospace;
        width:       72mm;
        padding:     4mm 3mm;
        font-size:   9pt;
        line-height: 1.35;
        color:       #000;
        background:  #fff;
      }

      /* ── Layout ── */
      .c   { text-align: center; }
      .r   { text-align: right; }
      .b   { font-weight: 900; }
      .f   { display: flex; justify-content: space-between; align-items: baseline; }
      .f span:last-child { font-variant-numeric: tabular-nums; }

      /* ── Tipografía ── */
      .big  { font-size: 11pt; font-weight: 900; }
      .med  { font-size: 10pt; }
      .sm   { font-size: 7.5pt; color: #333; }
      .mono { font-variant-numeric: tabular-nums; letter-spacing: .02em; }

      /* ── Separadores ── */
      .hr {
        border: none;
        border-bottom: 1px dashed #000;
        margin: 3mm 0;
      }
      .hr-solid {
        border: none;
        border-bottom: 2px solid #000;
        margin: 3mm 0;
      }

      /* ── Encabezado de ticket ── */
      .ticket-header { margin-bottom: 3mm; }
      .ticket-header .store { font-size: 13pt; font-weight: 900; letter-spacing: .05em; }
      .ticket-header .sub   { font-size: 8pt; color: #333; }

      /* ── Importe destacado ── */
      .total-amount {
        font-size: 14pt;
        font-weight: 900;
        text-align: center;
        margin: 3mm 0;
        letter-spacing: .03em;
        font-variant-numeric: tabular-nums;
      }

      /* ── Footer ── */
      .ticket-footer {
        margin-top: 3mm;
        font-size: 7pt;
        text-align: center;
        color: #444;
      }

      /* ── Firma ── */
      .firma-line {
        border-top: 1px solid #000;
        text-align: center;
        padding-top: 2mm;
        margin-top: 8mm;
        font-size: 8pt;
      }
    `,

    imprimirTicketVenta(v) {
      const w = window.open('','_blank','width=300');
      w.document.write(`<html><head><meta charset="utf-8"><style>${_pub._css}</style></head><body>
        <div class="ticket-header c">
          <div class="store">✂ FABIOLA</div>
          <div class="sub">Peluquería & Estética</div>
        </div>
        <div class="hr-solid"></div>
        <div class="f sm"><span>FECHA</span><span>${new Date().toLocaleDateString('es-CL', {day:'2-digit',month:'2-digit',year:'numeric'})}</span></div>
        <div class="f sm"><span>HORA</span><span>${new Date().toLocaleTimeString('es-CL',{hour:'2-digit',minute:'2-digit'})}</span></div>
        <div class="f sm"><span>PROFESIONAL</span><span class="b">${v.barber}</span></div>
        <div class="hr"></div>
        <div class="c b med">${v.name}</div>
        ${v.service ? `<div class="c sm">${v.service}</div>` : ''}
        <div class="total-amount">${fmt(v.price)}</div>
        <div class="hr"></div>
        <div class="f sm"><span>MÉTODO DE PAGO</span><span class="b">${v.method}</span></div>
        <div class="hr"></div>
        <div class="ticket-footer">
          <div>GRACIAS POR TU PREFERENCIA</div>
          <div>San Martín 443 · Castro · Chiloé</div>
          <div style="margin-top:2mm;">— SISTEMA TECNO JUMP —</div>
        </div>
      </body></html>`);
      w.document.close(); w.print(); w.close();
    },

    imprimirTicketCierre(c) {
      const w = window.open('','_blank','width=320');
      const barberRows = (c.perBarber||[]).map(r => `
        <div class="f b"><span>${r.nombre} (${r.cant} serv.)</span><span>${fmt(r.total)}</span></div>
        <div class="f sm"><span>  💵 ${fmt(r.ef)}</span><span>💳 ${fmt(r.tar)}</span><span>📱 ${fmt(r.tra)}</span></div>
        <div class="f sm"><span>  Comisión ${r.c||'?'}%</span><span>${fmt(Math.round(r.total*(r.c||0)/100))}</span></div>
        <div class="hr"></div>`).join('');
      w.document.write(`<html><head><style>${_pub._css}</style></head><body>
        <div class="c b big">✂ CIERRE DIARIO ✂</div>
        <div class="c b">PELUQUERÍA FABIOLA</div>
        <div class="c sm">San Martin 443, Castro</div>
        <div class="hr"></div>
        <div class="f"><span>FECHA:</span><span>${c.fecha}</span></div>
        <div class="hr"></div>
        <div class="b sm">VENTAS POR PROFESIONAL:</div>
        <div style="margin-top:4px;">${barberRows}</div>
        <div class="b sm">RESUMEN SISTEMA vs. FÍSICO:</div>
        <div class="hr"></div>
        <div class="f"><span>Efectivo SIS:</span><span>${fmt(c.sis?.ef||0)}</span></div>
        <div class="f"><span>Efectivo REAL:</span><span>${fmt(c.real.ef)}</span></div>
        <div class="f b"><span>Diferencia:</span><span>${fmtDiff(c.dif.ef)}</span></div>
        <div class="hr"></div>
        <div class="f"><span>Tarjeta SIS:</span><span>${fmt(c.sis?.tar||0)}</span></div>
        <div class="f"><span>Tarjeta REAL:</span><span>${fmt(c.real.tar)}</span></div>
        <div class="f b"><span>Diferencia:</span><span>${fmtDiff(c.dif.tar)}</span></div>
        <div class="hr"></div>
        <div class="f"><span>Transf. SIS:</span><span>${fmt(c.sis?.tra||0)}</span></div>
        <div class="f"><span>Transf. REAL:</span><span>${fmt(c.real.tra)}</span></div>
        <div class="f b"><span>Diferencia:</span><span>${fmtDiff(c.dif.tra)}</span></div>
        <div class="hr"></div>
        <div class="f b big"><span>TOTAL REAL:</span><span>${fmt(c.real.tot)}</span></div>
        <div class="hr"></div>
        <div class="c sm">SISTEMA POR TECNO JUMP</div>
      </body></html>`);
      w.document.close(); w.print(); w.close();
    },

    imprimirPagoStaff(nombre, cant, monto, f1, f2) {
      const w = window.open('','_blank','width=300');
      w.document.write(`<html><head><style>${_pub._css}</style></head><body>
        <div class="c b big">COMPROBANTE DE PAGO</div>
        <div class="c">FABIOLA</div><div class="hr"></div>
        <div class="f"><span>PROFESIONAL:</span><span>${nombre}</span></div>
        <div class="f"><span>DESDE:</span><span>${f1}</span></div>
        <div class="f"><span>HASTA:</span><span>${f2}</span></div>
        <div class="hr"></div>
        <div class="f"><span>SERVICIOS:</span><span>${cant}</span></div>
        <div class="f b big"><span>MONTO A PAGAR:</span><span>${fmt(monto)}</span></div>
        <div class="hr"></div><br><br>
        <div class="firma-line">FIRMA DE CONFORMIDAD</div>
        <div class="c sm" style="margin-top:3mm;">San Martín 443 · Castro · Chiloé</div>
      </body></html>`);
      w.document.close(); w.print(); w.close();
    },

    // ──── §10.15 MONITOR TV ───────────────────────────────────
    abrirMonitor() {
      _monWin = window.open('','FabiolaTV','width=1200,height=750,menubar=no,toolbar=no,location=no');
      _monWin.document.open();
      _monWin.document.write(_buildMonitorHTML());
      _monWin.document.close();
    },

    // ──── §10.X ESTADÍSTICAS (Solo Admin) ───────────────────
    _statsGetVentas(periodo) {
      const now  = Date.now();
      const ms   = { hoy: 86400000, semana: 7*86400000, mes: 30*86400000 };
      const desde = now - (ms[periodo] || ms.hoy);

      // Ventas del día actual (hoy real, aún no cerrado)
      const hoyVentas = (_data.hoy || []).filter(v => !v.type && new Date(v.timestamp).getTime() >= desde);

      // Ventas de cierres históricos dentro del período
      const histVentas = [];
      (_data.historial || []).forEach(c => {
        (c.detalle || []).forEach(v => {
          if (!v.type && new Date(v.timestamp).getTime() >= desde) histVentas.push(v);
        });
      });

      return [...hoyVentas, ...histVentas];
    },

    renderEstadisticas(periodo) {
      const ventas = _pub._statsGetVentas(periodo);
      const labels = { hoy: 'Hoy', semana: 'Últimos 7 días', mes: 'Últimos 30 días' };
      const labelEl = document.getElementById('statsPeriodoLabel');
      if (labelEl) labelEl.textContent = labels[periodo] || '';

      // Totales
      const total = ventas.reduce((a,v) => a + (v.price||0), 0);
      const ef    = ventas.filter(v=>v.method==='EFECTIVO').reduce((a,v)=>a+(v.price||0),0);
      const tar   = ventas.filter(v=>v.method==='TARJETA').reduce((a,v)=>a+(v.price||0),0);
      const tra   = ventas.filter(v=>v.method==='TRANSFERENCIA').reduce((a,v)=>a+(v.price||0),0);

      document.getElementById('statTotal').textContent = fmt(total);
      document.getElementById('statEfec').textContent  = fmt(ef);
      document.getElementById('statTar').textContent   = fmt(tar);
      document.getElementById('statTrans').textContent = fmt(tra);

      // KPI: Ticket promedio
      const cant = ventas.length;
      const prom = cant ? Math.round(total / cant) : 0;
      document.getElementById('kpiTicket').textContent    = fmt(prom);
      document.getElementById('kpiTicketSub').textContent = `${cant} servicio${cant !== 1 ? 's' : ''} en el período`;

      // KPI: Mejor barbero
      const barbMap = {};
      ventas.forEach(v => {
        if (!v.barber) return;
        if (!barbMap[v.barber]) barbMap[v.barber] = { total:0, cant:0 };
        barbMap[v.barber].total += (v.price||0);
        barbMap[v.barber].cant++;
      });
      const sortedBarb = Object.entries(barbMap).sort((a,b) => b[1].total - a[1].total);
      if (sortedBarb.length) {
        document.getElementById('kpiBarbero').textContent    = sortedBarb[0][0];
        document.getElementById('kpiBarberoSub').textContent = `${fmt(sortedBarb[0][1].total)} · ${sortedBarb[0][1].cant} servicios`;
      } else {
        document.getElementById('kpiBarbero').textContent    = '—';
        document.getElementById('kpiBarberoSub').textContent = 'Sin datos';
      }

      // KPI: Servicio top
      const srvMap = {};
      ventas.forEach(v => {
        if (!v.service) return;
        srvMap[v.service] = (srvMap[v.service] || 0) + 1;
      });
      const sortedSrv = Object.entries(srvMap).sort((a,b) => b[1] - a[1]);
      if (sortedSrv.length) {
        document.getElementById('kpiServicio').textContent    = sortedSrv[0][0];
        document.getElementById('kpiServicioSub').textContent = `${sortedSrv[0][1]} veces solicitado`;
      } else {
        document.getElementById('kpiServicio').textContent    = '—';
        document.getElementById('kpiServicioSub').textContent = 'Sin datos';
      }

      // Ranking de barberos con barra visual
      const maxBarb = sortedBarb.length ? sortedBarb[0][1].total : 1;
      document.getElementById('statBarberList').innerHTML = sortedBarb.length
        ? sortedBarb.map(([nombre, d], i) => {
            const pct = Math.round((d.total / maxBarb) * 100);
            const medals = ['🥇','🥈','🥉'];
            const bObj = _data.barberos.find(b => b.n === nombre);
            const av = bObj?.photo
              ? `<img src="${bObj.photo}" style="width:40px;height:40px;border-radius:50%;object-fit:cover;flex-shrink:0;">`
              : `<div style="width:40px;height:40px;border-radius:50%;background:#f1f5f9;display:flex;align-items:center;justify-content:center;font-weight:900;font-size:14px;color:#94a3b8;flex-shrink:0;">${nombre.charAt(0)}</div>`;
            return `
              <div class="flex items-center gap-4 p-3 rounded-2xl bg-slate-50">
                ${av}
                <div class="flex-1 min-w-0">
                  <div class="flex justify-between items-center mb-1">
                    <span class="font-black text-sm uppercase">${medals[i]||'  '} ${nombre}</span>
                    <span class="font-black text-emerald-700 text-sm">${fmt(d.total)}</span>
                  </div>
                  <div class="stat-bar-wrap">
                    <div class="stat-bar-fill ${i===0?'':'gold'}" style="width:${pct}%"></div>
                  </div>
                  <div class="text-[9px] text-slate-400 font-bold mt-1">${d.cant} servicios · Ticket prom. ${fmt(d.cant ? Math.round(d.total/d.cant) : 0)}</div>
                </div>
              </div>`;
          }).join('')
        : '<p class="text-center text-slate-300 text-[10px] font-black uppercase py-6">Sin datos en este período</p>';

      // Servicios más solicitados
      const maxSrv = sortedSrv.length ? sortedSrv[0][1] : 1;
      document.getElementById('statServicioList').innerHTML = sortedSrv.length
        ? sortedSrv.slice(0,8).map(([nombre, cnt], i) => {
            const pct = Math.round((cnt / maxSrv) * 100);
            const totalSrv = ventas.filter(v=>v.service===nombre).reduce((a,v)=>a+(v.price||0),0);
            return `
              <div class="flex items-center gap-4">
                <div class="w-6 text-center font-black text-[10px] text-slate-300">#${i+1}</div>
                <div class="flex-1 min-w-0">
                  <div class="flex justify-between items-center mb-1">
                    <span class="font-black text-xs uppercase truncate">${nombre}</span>
                    <span class="text-[10px] font-black text-slate-600">${cnt}x · ${fmt(totalSrv)}</span>
                  </div>
                  <div class="stat-bar-wrap">
                    <div class="stat-bar-fill blue" style="width:${pct}%"></div>
                  </div>
                </div>
              </div>`;
          }).join('')
        : '<p class="text-center text-slate-300 text-[10px] font-black uppercase py-4">Sin datos</p>';

      // Cierres del período
      const now2 = Date.now();
      const ms2  = { hoy: 86400000, semana: 7*86400000, mes: 30*86400000 };
      const desde2 = now2 - (ms2[periodo] || ms2.hoy);
      const cierresFiltrados = (_data.historial || []).filter(c => {
        const d = new Date(c.fullFecha + 'T00:00:00').getTime();
        return d >= desde2;
      }).reverse();

      document.getElementById('statCierreList').innerHTML = cierresFiltrados.length
        ? cierresFiltrados.map(c => `
            <div class="p-4 border border-slate-100 rounded-2xl bg-slate-50 flex justify-between items-center">
              <div>
                <div class="font-black text-xs uppercase">${c.fecha}</div>
                <div class="text-[9px] text-slate-400 font-bold mt-0.5">${(c.detalle||[]).filter(v=>!v.type).length} servicios</div>
              </div>
              <div class="text-right">
                <div class="font-black text-emerald-700">${fmt(c.sis?.tot||0)}</div>
                <div class="text-[8px] text-slate-400 font-bold uppercase">Sistema</div>
              </div>
            </div>`).join('')
        : '<p class="text-center text-slate-300 text-[10px] font-black uppercase py-4">Sin cierres en este período</p>';
    },

    filtrarStats(periodo, btn) {
      document.querySelectorAll('.periodo-btn').forEach(b => b.classList.remove('active'));
      if (btn) btn.classList.add('active');
      _pub.renderEstadisticas(periodo);
    },

    // ──── §10.16 UTILIDADES ───────────────────────────────────
    _toast(msg, color = '#16a34a') {
      const t = document.createElement('div');
      t.style.cssText = `position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:${color};color:#fff;
        padding:10px 22px;border-radius:12px;font-size:11px;font-weight:900;text-transform:uppercase;
        z-index:9999;letter-spacing:.05em;box-shadow:0 4px 20px rgba(0,0,0,.2);white-space:nowrap;`;
      t.textContent = msg;
      document.body.appendChild(t);
      setTimeout(() => t.remove(), 3200);
    }
  }; // fin _pub

  // ──────────────────────────────────────────────────────────────
  // §11  FACHADA PÚBLICA CONGELADA
  // window.app es solo un proxy de _pub; _data permanece privado.
  // Object.freeze impide monkey-patching desde la consola.
  // ──────────────────────────────────────────────────────────────
  window.app = Object.freeze({
    login:              ()    => _pub.login(),
    logout:             ()    => _pub.logout(),
    tab:                (t,b) => _pub.tab(t,b),
    reg:                ()    => _pub.reg(),
    next:               ()    => _pub.next(),
    openChange:         i     => _pub.openChange(i),
    confirmReAsignar:   ()    => _pub.confirmReAsignar(),
    ponerEnReposo:      i     => _pub.ponerEnReposo(i),
    openRetomar:        i     => _pub.openRetomar(i),
    confirmRetomar:     ()    => _pub.confirmRetomar(),
    prepP:              i     => _pub.prepP(i),
    pay:                ()    => _pub.pay(),
    render:             ()    => _pub.render(),
    renderCaja:         ()    => _pub.renderCaja(),
    renderCajero:       ()    => _pub.renderCajero(),
    regCajero:          ()    => _pub.regCajero(),
    priceCajero:        ()    => _pub.priceCajero(),
    renderAdmin:        ()    => _pub.renderAdmin(),
    renderStaff:        ()    => _pub.renderStaff(),
    calcDiff:           ()    => _pub.calcDiff(),
    buscarCierre:       ()    => _pub.buscarCierre(),
    confirmarCierre:    ()    => _pub.confirmarCierre(),
    verHistorialCierre: ()    => _pub.verHistorialCierre(),
    reimprimir:         i     => _pub.reimprimir(i),
    regGasto:           ()    => _pub.regGasto(),
    openM:              id    => _pub.openM(id),
    closeM:             ()    => _pub.closeM(),
    updateTimers:       ()    => _pub.updateTimers(),
    abrirMonitor:       ()    => _pub.abrirMonitor(),
    previewPhoto:       el    => _pub.previewPhoto(el),
    price:              ()    => _pub.price(),
    addB:               ()    => _pub.addB(),
    addS:               ()    => _pub.addS(),
    rmBarber:           i     => _pub.rmBarber(i),
    rmServicio:         i     => _pub.rmServicio(i),
    rmEspera:           i     => _pub.rmEspera(i),
    rmReposo:           i     => _pub.rmReposo(i),
    inB:                n     => _pub.inB(n),
    outB:               n     => _pub.outB(n),
    togglePausa:        n     => _pub.togglePausa(n),
    openEnviarCaja:     i     => _pub.openEnviarCaja(i),
    confirmarEnviarCaja:()    => _pub.confirmarEnviarCaja(),
    renderPendiente:    ()    => _pub.renderPendiente(),
    procesarPendiente:  i     => _pub.procesarPendiente(i),
    confirmarPendiente: ()    => _pub.confirmarPendiente(),
    openUserModal:      id    => _pub.openUserModal(id),
    saveAdminUser:      ()    => _pub.saveAdminUser(),
    deleteUser:         id    => _pub.deleteUser(id),
    toggleUserActive:   id    => _pub.toggleUserActive(id),
    imprimirPagoStaff:  (n,c,m,f1,f2) => _pub.imprimirPagoStaff(n,c,m,f1,f2),
    imprimirTicketVenta:   v  => _pub.imprimirTicketVenta(v),
    imprimirTicketCierre:  c  => _pub.imprimirTicketCierre(c),
    renderEstadisticas: p     => _pub.renderEstadisticas(p),
    filtrarStats:      (p,b)  => _pub.filtrarStats(p,b),
    _syncFromFirestore: ()    => _pub._syncFromFirestore(),
    // ⚠ _data NO expuesto — window.app.data === undefined
  });

  // Arrancar la inicialización al cargar
  _pub.init();

})(); // ← Fin del IIFE — _data y _currentUser permanecen privados
