/** @type {import('tailwindcss').Config} */
module.exports = {
  // Scan every source file that can emit Tailwind utility classes. The SPA
  // builds most of its markup as template strings inside app.js, and the HTML
  // shell + server-rendered fragments live in backend/index.tsx.
  content: [
    './backend/index.tsx',
    './frontend/static/app.js',
    './frontend/static/*.html'
  ],
  // The UI relies on arbitrary/dynamic utility classes (e.g. bg-${tone}-50)
  // that Tailwind cannot statically detect. Safelist the colour families and
  // common dynamic patterns so the production build keeps them.
  safelist: [
    { pattern: /^(bg|text|border)-(red|amber|emerald|teal|green|slate|blue|yellow)-(50|100|200|300|400|500|600|700|800)$/ },
    'hidden', 'opacity-50'
  ],
  theme: { extend: {} },
  plugins: []
}
