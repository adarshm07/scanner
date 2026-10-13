/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Geist", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      colors: {
        ink: "#0F1215",
        ink2: "#0A0D0F",
        panel: "#12171A",
        panel2: "#151A1E",
        hover: "#161B1F",
        line: "#262D33",
        line2: "#1F252A",
        edge: "#333B42",
        "edge-hover": "#4A555E",
        ink3: "#E3E7EA",
        text2: "#D2D8DC",
        text3: "#C9D0D5",
        muted: "#8D979F",
        dim: "#5E6870",
        sev: {
          critical: "#F0506E",
          high: "#F28C38",
          medium: "#D9B53C",
          low: "#6AA5E0",
        },
      },
      borderRadius: {
        DEFAULT: "3px",
      },
    },
  },
  plugins: [],
};
