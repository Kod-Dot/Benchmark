// Light, dark or the Windows setting. Light is the default. Kept in this
// computer's browser storage: a per-person preference, not part of any
// assessment.

export type Theme = 'system' | 'light' | 'dark';

const KEY = 'dca-theme';

export function savedTheme(): Theme {
  try {
    const t = localStorage.getItem(KEY);
    return t === 'system' || t === 'dark' ? t : 'light';
  } catch {
    return 'light';
  }
}

export function applyTheme(theme: Theme, save = false) {
  document.documentElement.setAttribute('data-theme', theme);
  if (!save) return;
  try {
    if (theme === 'light') localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, theme);
  } catch {
    // Storage blocked: the choice lasts until the app closes.
  }
}
