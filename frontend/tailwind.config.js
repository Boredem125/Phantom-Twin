/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        void:    '#F8F9FA', // clean soft off-white background
        surface: '#FFFFFF', // pure white card surface
        border:  '#E9ECEF', // delicate line border
        signal:  '#1A1D20', // primary highly-readable text
        muted:   '#6C757D', // muted supportive text
        phantom: '#D97706', // deep amber accent for decoy states
        threat:  '#DC2626', // strong crimson red for critical alerts
        warn:    '#EA580C', // vivid orange for medium/high warnings
        drift:   '#2563EB', // vibrant blue for drift/bootstrap indicators
        safe:    '#16A34A', // organic emerald green for normal states
      },
      boxShadow: {
        'soft': '0 2px 12px -3px rgba(0, 0, 0, 0.04), 0 4px 6px -2px rgba(0, 0, 0, 0.02)',
        'premium': '0 10px 30px -10px rgba(0, 0, 0, 0.06), 0 1px 3px rgba(0, 0, 0, 0.02)',
        'active': '0 10px 25px -5px rgba(217, 119, 6, 0.1), 0 1px 3px rgba(217, 119, 6, 0.05)',
      }
    },
  },
  plugins: [],
}
