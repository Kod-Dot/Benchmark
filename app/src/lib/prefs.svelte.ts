// Per-person display preferences: zoom and animations. Kept in this
// computer's browser storage, like the theme (lib/theme.ts).

import { getCurrentWebview } from '@tauri-apps/api/webview';
import { inDesktopApp } from './backend';

export const ZOOM_STEPS = [0.8, 0.9, 1, 1.1, 1.25, 1.4, 1.5] as const;
export type Motion = 'on' | 'off';

const ZOOM_KEY = 'dca-zoom';
const MOTION_KEY = 'dca-motion';

function read(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string | null) {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // Storage blocked: the choice lasts until the app closes.
  }
}

export function savedZoom(): number {
  const z = Number(read(ZOOM_KEY));
  return (ZOOM_STEPS as readonly number[]).includes(z) ? z : 1;
}

/** Zooms the whole window. The desktop app zooms the web view itself, so
 * every measurement stays consistent; the browser preview uses CSS zoom. */
export function applyZoom(zoom: number, save = false) {
  if (inDesktopApp) {
    getCurrentWebview()
      .setZoom(zoom)
      .catch(() => {
        document.documentElement.style.zoom = String(zoom);
      });
  } else {
    document.documentElement.style.zoom = zoom === 1 ? '' : String(zoom);
  }
  if (save) write(ZOOM_KEY, zoom === 1 ? null : String(zoom));
}

/** The next zoom step up (+1) or down (-1) from the current one. */
export function stepZoom(current: number, dir: 1 | -1): number {
  const i = ZOOM_STEPS.findIndex((z) => z >= current - 0.001);
  const at = i < 0 ? ZOOM_STEPS.length - 1 : i;
  return ZOOM_STEPS[Math.min(Math.max(at + dir, 0), ZOOM_STEPS.length - 1)];
}

export function savedMotion(): Motion {
  return read(MOTION_KEY) === 'off' ? 'off' : 'on';
}

export function applyMotion(motion: Motion, save = false) {
  if (motion === 'off') document.documentElement.setAttribute('data-motion', 'off');
  else document.documentElement.removeAttribute('data-motion');
  if (save) write(MOTION_KEY, motion === 'off' ? 'off' : null);
}

/** Shared zoom state, so Settings and the Ctrl+/- keys agree. */
export const display = $state({ zoom: savedZoom(), motion: savedMotion() });

export function setZoom(z: number) {
  display.zoom = z;
  applyZoom(z, true);
}

export function setMotion(m: Motion) {
  display.motion = m;
  applyMotion(m, true);
}

/** Marks an element as scrolling for a moment, so its scrollbar shows (base.css). */
export function watchScrolling() {
  const timers = new WeakMap<Element, number>();
  document.addEventListener(
    'scroll',
    (e) => {
      const el = e.target === document ? document.documentElement : (e.target as Element);
      if (!(el instanceof Element)) return;
      if (!timers.has(el)) el.setAttribute('data-scrolling', '');
      clearTimeout(timers.get(el));
      timers.set(
        el,
        window.setTimeout(() => {
          el.removeAttribute('data-scrolling');
          timers.delete(el);
        }, 900),
      );
    },
    { capture: true, passive: true },
  );
}

/** Ctrl + / Ctrl - / Ctrl 0 zoom anywhere in the app. */
export function zoomKeys() {
  window.addEventListener('keydown', (e) => {
    if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
    if (e.key === '=' || e.key === '+') setZoom(stepZoom(display.zoom, 1));
    else if (e.key === '-' || e.key === '_') setZoom(stepZoom(display.zoom, -1));
    else if (e.key === '0') setZoom(1);
    else return;
    e.preventDefault();
  });
}
