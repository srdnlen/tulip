import { useEffect, useState } from "react";

const prefersDarkModeQuery = "(prefers-color-scheme: dark)";

function getPrefersDarkMode() {
  return (
    typeof window !== "undefined" &&
    window.matchMedia(prefersDarkModeQuery).matches
  );
}

export function usePrefersDarkMode() {
  const [prefersDarkMode, setPrefersDarkMode] =
    useState(getPrefersDarkMode);

  useEffect(() => {
    const mediaQuery = window.matchMedia(prefersDarkModeQuery);
    const handleChange = (event: MediaQueryListEvent) => {
      setPrefersDarkMode(event.matches);
    };

    setPrefersDarkMode(mediaQuery.matches);
    mediaQuery.addEventListener("change", handleChange);

    return () => {
      mediaQuery.removeEventListener("change", handleChange);
    };
  }, []);

  return prefersDarkMode;
}
