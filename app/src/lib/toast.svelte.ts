// A short confirmation at the bottom of the window ("Copied"). One at a time.

export const toastState = $state<{ text: string; id: number } | { text: null; id: number }>({ text: null, id: 0 });
let timer = 0;

export function toast(text: string) {
  toastState.text = text;
  toastState.id++;
  clearTimeout(timer);
  timer = window.setTimeout(() => (toastState.text = null), 2200);
}

/** Copies text and confirms it; says so when the clipboard is unavailable. */
export async function copyText(text: string, what = 'Copied') {
  try {
    await navigator.clipboard.writeText(text);
    toast(what);
  } catch {
    toast('Could not copy: the clipboard is not available');
  }
}
