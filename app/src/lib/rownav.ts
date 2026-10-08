// Keyboard use of clickable table rows (tr.row): one row is in the tab order,
// the arrow keys, Home and End move between rows, and Enter opens the row as
// a click would. Rows can change at any time (filters, sorting, paging).
//
// In a virtualized table (lib/virtual.svelte.ts) rows carry data-index, their
// position in the whole list, and the table aria-rowcount. A move to a row
// that is not rendered asks the table to scroll it into view ('rowreveal')
// and focuses it once it is there.

export function rowNav(table: HTMLTableElement) {
  const rows = () => [...table.querySelectorAll<HTMLTableRowElement>('tbody tr.row')];
  const indexOf = (r: Element, all: HTMLTableRowElement[]) => {
    const d = (r as HTMLElement).dataset.index;
    return d === undefined ? all.indexOf(r as HTMLTableRowElement) : Number(d);
  };
  const total = (all: HTMLTableRowElement[]) => {
    const n = Number(table.getAttribute('aria-rowcount'));
    // aria-rowcount includes the header row.
    return n > 0 ? n - 1 : all.length;
  };
  const rowAt = (i: number, all: HTMLTableRowElement[]) => all.find((r) => indexOf(r, all) === i);
  let current = 0;

  function sync() {
    const all = rows();
    if (!all.length) return;
    if (current >= total(all)) current = Math.max(0, total(all) - 1);
    // Keep exactly one row in the tab order, the current one if it is rendered.
    const cur = rowAt(current, all) ?? all[0];
    for (const r of all) r.setAttribute('tabindex', r === cur ? '0' : '-1');
  }

  let attempt = 0;
  function focus(i: number) {
    const all = rows();
    if (!all.length) return;
    current = Math.min(Math.max(i, 0), total(all) - 1);
    const row = rowAt(current, all);
    if (row) {
      sync();
      row.focus();
      return;
    }
    // Not rendered yet: have the table scroll to it, then try again.
    table.dispatchEvent(new CustomEvent('rowreveal', { detail: current }));
    const mine = ++attempt;
    let tries = 0;
    const retry = () => {
      if (mine !== attempt) return;
      const r = rowAt(current, rows());
      if (r) {
        sync();
        r.focus();
      } else if (++tries < 10) requestAnimationFrame(retry);
    };
    requestAnimationFrame(retry);
  }

  function onKey(e: KeyboardEvent) {
    const row = (e.target as HTMLElement).closest('tr.row');
    if (!row || e.target !== row) return;
    const i = indexOf(row, rows());
    const moves: Record<string, number> = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: Infinity, PageDown: i + 10, PageUp: i - 10 };
    if (e.key in moves) {
      e.preventDefault();
      focus(moves[e.key]);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      (row as HTMLElement).click();
    }
  }

  function onFocusIn(e: FocusEvent) {
    const row = (e.target as HTMLElement).closest('tr.row');
    if (!row) return;
    const i = indexOf(row, rows());
    if (i >= 0 && i !== current) {
      current = i;
      sync();
    }
  }

  const observer = new MutationObserver(sync);
  observer.observe(table, { childList: true, subtree: true });
  table.addEventListener('keydown', onKey);
  table.addEventListener('focusin', onFocusIn);
  sync();

  return {
    destroy() {
      observer.disconnect();
      table.removeEventListener('keydown', onKey);
      table.removeEventListener('focusin', onFocusIn);
    },
  };
}
