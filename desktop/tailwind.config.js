/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "media",
  theme: {
    extend: {
      fontFamily: {
        // Match the host OS rather than shipping a typeface: the app should
        // read as part of macOS, not as a web page inside it.
        sans: [
          "-apple-system",
          "BlinkMacSystemFont",
          "SF Pro Text",
          "Helvetica Neue",
          "sans-serif",
        ],
        mono: ["SF Mono", "ui-monospace", "Menlo", "monospace"],
      },
      fontSize: {
        "2xs": ["10px", "14px"],
        xs: ["11px", "15px"],
        sm: ["12px", "17px"],
        base: ["13px", "18px"],
        lg: ["15px", "20px"],
        xl: ["18px", "24px"],
      },
    },
  },
  plugins: [],
};
