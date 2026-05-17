/**
 * ══════════════════════════════════════════════════════════════
 *  config.js — Configuración e Inicialización de Firebase
 *  Fabiola Gestión Pro · Tecno Jump
 * ══════════════════════════════════════════════════════════════
 *
 *  Este archivo inicializa Firebase y expone la instancia `db`
 *  como variable global para que app.js pueda usarla.
 *
 *  ORDEN DE CARGA (en index.html):
 *    1. firebase-app-compat.js    ← SDK core
 *    2. firebase-firestore-compat.js ← Firestore
 *    3. config.js                 ← este archivo (init + expone db)
 *    4. app.js                    ← lógica principal (usa db)
 *
 *  ╔══════════════════════════════════════════════════════════╗
 *  ║  REGLAS DE SEGURIDAD DE FIRESTORE (IMPORTANTE)          ║
 *  ║  Configura estas reglas en Firebase Console →            ║
 *  ║  Firestore → Reglas:                                     ║
 *  ║                                                          ║
 *  ║  rules_version = '2';                                    ║
 *  ║  service cloud.firestore {                               ║
 *  ║    match /databases/{db}/documents {                     ║
 *  ║      // Estado operacional: solo escritura autenticada   ║
 *  ║      match /barberia/{doc} {                             ║
 *  ║        allow read:  if true;                             ║
 *  ║        allow write: if true; // → restringir con Auth    ║
 *  ║      }                                                   ║
 *  ║      // Historial de cierres: solo lectura pública       ║
 *  ║      match /historial/{doc} {                            ║
 *  ║        allow read:  if true;                             ║
 *  ║        allow write: if true;                             ║
 *  ║      }                                                   ║
 *  ║      // Audit log: solo escritura, nunca borrar          ║
 *  ║      match /auditLog/{doc} {                             ║
 *  ║        allow read:  if false; // solo en consola Firebase║
 *  ║        allow write: if true;                             ║
 *  ║        allow delete: if false;                           ║
 *  ║      }                                                   ║
 *  ║    }                                                     ║
 *  ║  }                                                       ║
 *  ╚══════════════════════════════════════════════════════════╝
 *
 *  ÍNDICES RECOMENDADOS (Firestore Console → Índices):
 *    Colección: auditLog
 *    Campos: userId ASC, timestamp DESC
 *    Campos: accion ASC, timestamp DESC
 */

// ──────────────────────────────────────────────────────────────
//  Credenciales del proyecto Firebase
//  (la API key de Firebase para web es pública por diseño;
//   la seguridad real se controla con las Reglas de Firestore)
// ──────────────────────────────────────────────────────────────
const firebaseConfig = {
  apiKey:            "AIzaSyCoUhl8XKs4lXdePXrrTxOaKel3cDQxVQc",
  authDomain:        "barberia-22fc2.firebaseapp.com",
  projectId:         "barberia-22fc2",
  storageBucket:     "barberia-22fc2.firebasestorage.app",
  messagingSenderId: "345417565286",
  appId:             "1:345417565286:web:9cf4a36fef299217ad99a7",
  measurementId:     "G-01Y8EJ55DB",
};

// ──────────────────────────────────────────────────────────────
//  Inicialización — previene doble init si el script se carga 2x
// ──────────────────────────────────────────────────────────────
if (!firebase.apps.length) {
  firebase.initializeApp(firebaseConfig);
} else {
  firebase.app(); // reutiliza la app ya inicializada
}

// ──────────────────────────────────────────────────────────────
//  Instancia de Firestore — disponible globalmente para app.js
// ──────────────────────────────────────────────────────────────
const db = firebase.firestore();

// Configuración de caché offline (opcional pero recomendado):
// Permite que la app funcione momentáneamente sin internet y
// sincronice cuando se restaure la conexión.
db.enablePersistence({ synchronizeTabs: true })
  .catch(err => {
    if (err.code === 'failed-precondition') {
      // Múltiples pestañas abiertas — la persistencia solo funciona en una
      console.info('[Firebase] Persistencia offline desactivada (múltiples pestañas).');
    } else if (err.code === 'unimplemented') {
      // El navegador no soporta la API de persistencia
      console.info('[Firebase] Persistencia offline no soportada en este navegador.');
    }
  });

// ──────────────────────────────────────────────────────────────
//  Estado de conexión (útil para mostrar indicadores en la UI)
// ──────────────────────────────────────────────────────────────
const _connRef = db.collection('_meta').doc('conexion');
// Nota: el documento _meta/conexion no necesita existir;
// Firestore detecta la conectividad internamente. Esta referencia
// se puede usar en el futuro para mostrar un badge de "online/offline".

console.info(
  '%c🔥 Firebase Firestore conectado',
  'color:#16a34a;font-weight:900;font-size:12px;',
  '| Proyecto:', firebaseConfig.projectId
);
