import { useEffect, useState } from "react";

const prefersDarkModeQuery = "(prefers-color-scheme: dark)";
const theme_key = "dark_mode";

export function usePrefersDarkMode() {
  const [prefersDarkMode, setPrefersDarkMode] = useState<boolean>(() => {
    if (typeof window === "undefined") {
      return false;
    }

    const stored = localStorage.getItem(theme_key);

    if (stored !== null) {
      return JSON.parse(stored);
    }

    return window.matchMedia(prefersDarkModeQuery).matches;
  });

  useEffect(() => {
    localStorage.setItem(theme_key, JSON.stringify(prefersDarkMode));
    document.documentElement.classList.toggle("dark", prefersDarkMode);
  }, [prefersDarkMode]);

  return [prefersDarkMode, setPrefersDarkMode] as const;
}