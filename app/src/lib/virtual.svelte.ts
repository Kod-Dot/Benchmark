// Renders only the rows of a long table that are on screen, plus a margin,
// so a directory of 500,000 objects scrolls and filters as fast as one of
// 500. Rows can differ in height: the window measures the rows it renders and
// sizes the space above and below from their average.
//
// Use: `const win = new VirtualRows()`, put `use:win.rows={count}` on the
// <tbody>, render `rows.slice(win.start, win.end)` with `data-index` set to
// the row's position in the whole list, and a spacer row of `win.before` px
// above and `win.after(count)` px below.

const OVERSCAN = 12;
const FIRST_RENDER = 60;

/** The element the page scrolls in: the nearest one marked data-scroller.
 * Wrappers that only scroll sideways (overflow-x) report overflow-y auto
 * too, so the computed style alone would pick them. */
function scrollParent(el: HTMLElement): HTMLElement {
  return el.closest<HTMLElement>('[data-scroller]') ?? (document.scrollingElement as HTMLElement);
}

export class VirtualRows {
  start = $state(0);
  end = $state(FIRST_RENDER);
  rowHeight = $state(44);

  get before() {
    return this.start * this.rowHeight;
  }

  after(count: number) {
    return Math.max(0, count - this.end) * this.rowHeight;
  }

  rows = (tbody: HTMLElement, initial: number) => {
    let count = initial;
    const scroller = scrollParent(tbody);
    const table = tbody.closest('table');

    const measure = () => {
      const rendered = tbody.querySelectorAll<HTMLElement>(':scope > tr[data-index]');
      if (!rendered.length) return;
      let total = 0;
      for (const r of rendered) total += r.getBoundingClientRect().height;
      const h = total / rendered.length;
      // Small differences are rounding; acting on them would never settle.
      if (h > 0 && Math.abs(h - this.rowHeight) > 2) this.rowHeight = h;
    };

    const compute = () => {
      const view = scroller.getBoundingClientRect();
      const top = tbody.getBoundingClientRect().top - view.top;
      const from = Math.max(0, -top);
      const to = Math.max(0, view.height - top);
      const h = this.rowHeight;
      // A filter can shorten the list below where it was scrolled to.
      const start = Math.min(Math.max(0, Math.floor(from / h) - OVERSCAN), Math.max(0, count - FIRST_RENDER));
      const end = Math.min(count, Math.max(Math.ceil(to / h) + OVERSCAN, start + FIRST_RENDER));
      if (start !== this.start) this.start = start;
      if (end !== this.end) this.end = end;
    };

    let frame = 0;
    const schedule = () => {
      if (frame) return;
      frame = requestAnimationFrame(() => {
        frame = 0;
        measure();
        compute();
      });
    };

    /** Scrolls row `index` into view, for keyboard moves past the rendered rows. */
    const reveal = (e: Event) => {
      const index = (e as CustomEvent<number>).detail;
      const view = scroller.getBoundingClientRect();
      const top = tbody.getBoundingClientRect().top - view.top + scroller.scrollTop;
      const y = top + index * this.rowHeight;
      if (y < scroller.scrollTop || y + this.rowHeight > scroller.scrollTop + view.height)
        scroller.scrollTop = y - view.height / 2;
      compute();
    };

    const target = scroller === document.scrollingElement ? window : scroller;
    target.addEventListener('scroll', schedule, { passive: true });
    const resize = new ResizeObserver(schedule);
    resize.observe(scroller);
    table?.addEventListener('rowreveal', reveal);
    compute();
    schedule();

    return {
      update(next: number) {
        count = next;
        compute();
        schedule();
      },
      destroy() {
        cancelAnimationFrame(frame);
        target.removeEventListener('scroll', schedule);
        resize.disconnect();
        table?.removeEventListener('rowreveal', reveal);
      },
    };
  };
}
