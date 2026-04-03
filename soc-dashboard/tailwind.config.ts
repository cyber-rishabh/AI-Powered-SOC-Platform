import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ["'JetBrains Mono'", "'Fira Code'", "Consolas", "monospace"],
      },
      colors: {
        neon: "#00ff88",
        "neon-dim": "#00cc6a",
        "neon-glow": "rgba(0,255,136,0.15)",
        bg: "#0a0a0a",
        "bg-panel": "#0d0d0d",
        "bg-card": "#111111",
        "bg-hover": "#161616",
        border: "#1a1a1a",
        "border-bright": "#252525",
        critical: "#ff3366",
        high: "#ff6633",
        medium: "#ffaa00",
        low: "#00ff88",
        muted: "#444444",
        "text-dim": "#666666",
        "text-mid": "#999999",
      },
      boxShadow: {
        neon: "0 0 20px rgba(0,255,136,0.2), 0 0 40px rgba(0,255,136,0.05)",
        "neon-sm": "0 0 10px rgba(0,255,136,0.15)",
        "panel": "0 0 0 1px #1a1a1a, 0 4px 24px rgba(0,0,0,0.6)",
      },
      animation: {
        "pulse-neon": "pulseNeon 2s ease-in-out infinite",
        "scan": "scan 3s linear infinite",
        "blink": "blink 1s step-end infinite",
        "fade-in": "fadeIn 0.3s ease-out",
        "slide-up": "slideUp 0.3s ease-out",
      },
      keyframes: {
        pulseNeon: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.6" },
        },
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100vh)" },
        },
        blink: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0" },
        },
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        slideUp: {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
