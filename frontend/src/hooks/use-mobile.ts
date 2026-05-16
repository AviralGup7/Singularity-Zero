import { useEffect, useState } from "react";

export function useIsMobile(mobileBreakpoint = 768) {
   
  const [isMobile, setIsMobile] = useState(() => window.innerWidth < mobileBreakpoint);

  useEffect(() => {
    const mediaQuery = window.matchMedia(`(max-width: ${mobileBreakpoint - 1}px)`);

    function handleChange() {
      setIsMobile(window.innerWidth < mobileBreakpoint);
    }

    mediaQuery.addEventListener("change", handleChange);
    return () => mediaQuery.removeEventListener("change", handleChange);
   
  }, [mobileBreakpoint]);

  return isMobile;
}
