/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        './pages/**/*.{js,ts,jsx,tsx,mdx}',
        './components/**/*.{js,ts,jsx,tsx,mdx}',
        './app/**/*.{js,ts,jsx,tsx,mdx}',
    ],
    theme: {
        extend: {
            colors: {
                // CloudQuery brand colors
                primary: {
                    50: '#f0f9ff',
                    100: '#e0f2fe',
                    200: '#bae6fd',
                    300: '#7dd3fc',
                    400: '#38bdf8',
                    500: '#0ea5e9',
                    600: '#0284c7',
                    700: '#0369a1',
                    800: '#075985',
                    900: '#0c4a6e',
                },
                // CloudQuery brand colors (Visual Analysis)
                cloudquery: {
                    // Primary Colors
                    logoGreen: '#00D4AA',        // Logo Green: ~#00D4AA (circular logo background)
                    ctaGreen: '#00C48C',         // CTA Button Green: ~#00C48C (Start for Free button)
                    bgDarkTeal: '#0D2B2F',       // Background Dark Teal: ~#0D2B2F (main dark background)
                    bgGradient: '#1A4A52',       // Background Gradient: ~#1A4A52 (lighter teal areas)

                    // Supporting Colors
                    textWhite: '#FFFFFF',        // Text White: #FFFFFF (primary text)

                    // Legacy colors for backward compatibility
                    blue: '#00D4AA',             // Map to logo green
                    darkBlue: '#0D2B2F',         // Map to dark teal
                    lightBlue: '#1A4A52',        // Map to gradient teal
                    gray: '#64748b',
                    darkGray: '#334155',
                },
                // Security severity colors
                severity: {
                    critical: '#dc2626',
                    high: '#ea580c',
                    medium: '#d97706',
                    low: '#65a30d',
                    info: '#0284c7',
                },
                // Status colors
                status: {
                    success: '#16a34a',
                    warning: '#d97706',
                    error: '#dc2626',
                    info: '#0284c7',
                }
            },
            fontFamily: {
                sans: ['Inter', 'system-ui', 'sans-serif'],
                mono: ['JetBrains Mono', 'monospace'],
            },
            animation: {
                'fade-in': 'fadeIn 0.5s ease-in-out',
                'slide-in': 'slideIn 0.3s ease-out',
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
            },
            keyframes: {
                fadeIn: {
                    '0%': { opacity: '0' },
                    '100%': { opacity: '1' },
                },
                slideIn: {
                    '0%': { transform: 'translateY(-10px)', opacity: '0' },
                    '100%': { transform: 'translateY(0)', opacity: '1' },
                },
            },
        },
    },
    plugins: [],
}
