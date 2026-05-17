/**
 * tailwind.config.js — Fabiola Gestión Pro
 * ════════════════════════════════════════════════════════════════
 *
 * Configuración de Tailwind CSS para compilación en PRODUCCIÓN.
 *
 * CÓMO COMPILAR:
 *   npm run build        → genera dist/output.css optimizado
 *   npm run build:watch  → modo watch durante desarrollo
 *
 * Luego en index.html reemplaza:
 *   <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
 * por:
 *   <link rel="stylesheet" href="./dist/output.css">
 *
 * ════════════════════════════════════════════════════════════════
 */

/** @type {import('tailwindcss').Config} */
module.exports = {
  // Escanear solo el HTML principal (y cualquier JS si se separa en módulos)
  content: [
    './index.html',
    './app.js',       // si usas clases dinámicas en template strings
  ],

  theme: {
    extend: {
      // Colores de marca Fabiola
      colors: {
        brand: {
          green:  '#16a34a',
          dark:   '#0f172a',
          bg:     '#f8fafc',
        },
      },

      // Fuentes usadas en la app
      fontFamily: {
        sans:  ['Inter', 'system-ui', 'sans-serif'],
        mono:  ['JetBrains Mono', 'monospace'],
      },

      // Animaciones personalizadas ya definidas en styles.css
      // Se declaran aquí solo para que el purger no las elimine
      animation: {
        'p-glow':     'pGlow 2s ease-in-out infinite',
        'blink':      'blink 1.5s infinite',
        'pulse-pago': 'pulsePago 2s ease-in-out infinite',
      },
    },
  },

  plugins: [],
};
