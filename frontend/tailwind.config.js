/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'cyber-bg': '#0a0e1a',
        'cyber-surface': '#111827',
        'cyber-border': '#1e293b',
        'cyber-card': '#0f172a',
        'cyber-hover': '#1a2332',
        'neon-green': '#00ff88',
        'neon-blue': '#00d4ff',
        'neon-red': '#ef4444',
        'neon-yellow': '#eab308',
        'neon-purple': '#a855f7',
        'neon-orange': '#f97316',
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Fira Code', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
      },
      boxShadow: {
        'neon-green': '0 0 5px #00ff88, 0 0 20px rgba(0, 255, 136, 0.15)',
        'neon-blue': '0 0 5px #00d4ff, 0 0 20px rgba(0, 212, 255, 0.15)',
        'neon-red': '0 0 5px #ef4444, 0 0 20px rgba(239, 68, 68, 0.15)',
        'neon-yellow': '0 0 5px #eab308, 0 0 20px rgba(234, 179, 8, 0.15)',
        'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.37)',
      },
      animation: {
        'pulse-neon': 'pulse-neon 2s ease-in-out infinite',
        'scan': 'scan 3s ease-in-out infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'slide-up': 'slide-up 0.5s ease-out',
        'fade-in': 'fade-in 0.3s ease-out',
        'typing': 'typing 1.5s steps(20) infinite',
        'border-flow': 'border-flow 3s linear infinite',
      },
      keyframes: {
        'pulse-neon': {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.5 },
        },
        'scan': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        'glow': {
          '0%': { boxShadow: '0 0 5px #00ff88, 0 0 10px rgba(0, 255, 136, 0.2)' },
          '100%': { boxShadow: '0 0 10px #00ff88, 0 0 30px rgba(0, 255, 136, 0.4)' },
        },
        'slide-up': {
          '0%': { transform: 'translateY(20px)', opacity: 0 },
          '100%': { transform: 'translateY(0)', opacity: 1 },
        },
        'fade-in': {
          '0%': { opacity: 0 },
          '100%': { opacity: 1 },
        },
        'typing': {
          '0%': { width: '0' },
          '50%': { width: '100%' },
          '100%': { width: '0' },
        },
        'border-flow': {
          '0%': { backgroundPosition: '0% 50%' },
          '100%': { backgroundPosition: '200% 50%' },
        },
      },
      backgroundImage: {
        'grid-pattern': 'linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px)',
      },
      backgroundSize: {
        'grid': '50px 50px',
      },
    },
  },
  plugins: [],
};
