import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "Segoe UI", "system-ui", "sans-serif"]
      },
      colors: {
        ink: "#071019",
        panel: "#101923",
        edge: "#223042",
        azure: "#32a4ff",
        signal: "#25d0a2",
        danger: "#ff5f66",
        amber: "#f7b955"
      },
      boxShadow: {
        glow: "0 0 36px rgba(50, 164, 255, 0.18)"
      }
    }
  },
  plugins: []
} satisfies Config;

