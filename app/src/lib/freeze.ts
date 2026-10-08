// Frozen page headers: `use:freeze` on a page's toolbar keeps it at the top
// of the scrolling page (.freeze in base.css), publishes its height as
// --freeze-h so table headers stop just below it, and adds .stuck once the
// page has scrolled, for a soft shadow.

export function freeze(el: HTMLElement) {
  el.classList.add('freeze');
  const scroller = el.closest<HTMLElement>('[data-scroller]');
  if (!scroller) return {};
  const publish = () => scroller.style.setProperty('--freeze-h', `${el.offsetHeight}px`);
  // Set it now so the table header never pins behind an unmeasured toolbar.
  publish();
  const size = new ResizeObserver(publish);
  size.observe(el);
  const onScroll = () => el.classList.toggle('stuck', scroller.scrollTop > 2);
  scroller.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
  return {
    destroy() {
      size.disconnect();
      scroller.removeEventListener('scroll', onScroll);
      scroller.style.removeProperty('--freeze-h');
    },
  };
}
