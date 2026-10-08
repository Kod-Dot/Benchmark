// Opens external links in the system's default browser. In the desktop app a
// plain <a href="http..."> would navigate the app's own window, so a click on
// any external link inside the element this action is on is sent to the Rust
// open_url command instead. In the browser preview the link opens normally.

import { inDesktopApp, openUrl } from './backend';
import { toast } from './toast.svelte';

export function externalLinks(el: HTMLElement) {
  function onClick(e: MouseEvent) {
    if (!inDesktopApp || e.defaultPrevented || e.button !== 0) return;
    const a = (e.target as HTMLElement).closest('a');
    const href = a?.getAttribute('href') ?? '';
    if (!a || !/^https?:\/\//i.test(href)) return;
    e.preventDefault();
    openUrl(href).catch(() => toast('Could not open the link in your browser'));
  }
  el.addEventListener('click', onClick);
  return {
    destroy() {
      el.removeEventListener('click', onClick);
    },
  };
}
