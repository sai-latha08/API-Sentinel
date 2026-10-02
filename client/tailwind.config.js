/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        sentinel: {
          50: '#F5F3FF',   // Light Violet
          100: '#EDE9FE',  // Soft Lavender
          200: '#DDD6FE',
          300: '#C4B5FD',
          400: '#A78BFA',
          500: '#8B5CF6',
          600: '#7C3AED',
          700: '#6D28D9',  // Primary Violet
          800: '#5B21B6',
          900: '#4C1D95',  // Deep Violet
          950: '#2E1065',
        },
        surface: {
          DEFAULT: '#FFFFFF',
          muted: '#FAFAFA',
          subtle: '#F4F4F5',
        },
        ink: {
          DEFAULT: '#18181B', // Dark Text
          muted: '#71717A',   // Secondary Text
          subtle: '#A1A1AA',
        },
        edge: {
          DEFAULT: '#E4E4E7', // Border
          strong: '#D4D4D8',
          subtle: '#F4F4F5',
        },
        severity: {
          critical: '#DC2626',
          criticalBg: '#FEF2F2',
          criticalBorder: '#FECACA',
          high: '#EA580C',
          highBg: '#FFF7ED',
          highBorder: '#FFEDD5',
          medium: '#D97706',
          mediumBg: '#FFFBEB',
          mediumBorder: '#FEF3C7',
          low: '#2563EB',
          lowBg: '#EFF6FF',
          lowBorder: '#DBEAFE',
          info: '#4B5563',
          infoBg: '#F3F4F6',
          infoBorder: '#E5E7EB',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
      },
      boxShadow: {
        'card': '0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05)',
        'card-hover': '0 10px 15px -3px rgba(109, 40, 217, 0.07), 0 4px 6px -4px rgba(109, 40, 217, 0.05)',
        'subtle': '0 1px 2px 0 rgba(0, 0, 0, 0.04)',
        'modal': '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.05)',
        'glow-violet': '0 0 20px -5px rgba(109, 40, 217, 0.25)',
      }
    },
  },
  plugins: [],
}
