/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      colors: {
        bg: 'var(--bg)',
        surface: 'var(--surface)',
        'surface-2': 'var(--surface-2)',
        line: 'var(--line)',
        fg: 'var(--fg)',
        muted: 'var(--muted)',
        accent: 'var(--accent)',
        'accent-hover': 'var(--accent-hover)',
        'accent-soft': 'var(--accent-soft)',
        // Severity colors: ONLY for badges, score bars, status, and the AI card's left border
        'sev-low': 'var(--sev-low)',
        'sev-low-bg': 'var(--sev-low-bg)',
        'sev-medium': 'var(--sev-medium)',
        'sev-medium-bg': 'var(--sev-medium-bg)',
        'sev-high': 'var(--sev-high)',
        'sev-high-bg': 'var(--sev-high-bg)',
        'sev-critical': 'var(--sev-critical)',
        'sev-critical-bg': 'var(--sev-critical-bg)',
      },
    },
  },
  plugins: [],
}
