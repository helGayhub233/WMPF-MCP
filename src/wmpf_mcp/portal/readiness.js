// Executed in a real rendering context. Arguments are JSON, never source interpolation.
((selector, key, binding, timeoutMs) => {
  if (typeof document !== 'object' || typeof MutationObserver !== 'function')
    return { watching: false, reason: 'no_document' };
  let observer, resize, timer, finished = false;
  const watchedImages = new Set();
  let last = { visible_matches: 0, pending_images: 0, failed_images: 0, fonts_loading: false };
  const events = ['DOMContentLoaded', 'load', 'error', 'resize', 'scroll', 'transitionend', 'animationend'];
  const visible = el => {
    if (!el.getClientRects().length) return false;
    for (let node = el; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.display === 'none' || style.visibility !== 'visible' || Number(style.opacity) === 0) return false;
    }
    try {
      for (let view = window; view.frameElement; view = view.parent) {
        const frame = view.frameElement;
        const parentStyle = frame.ownerDocument.defaultView.getComputedStyle(frame);
        if (!frame.getClientRects().length || parentStyle.display === 'none' ||
            parentStyle.visibility !== 'visible' || Number(parentStyle.opacity) === 0) return false;
      }
    } catch { /* Cross-origin parents cannot be inspected; report the selected frame. */ }
    return true;
  };
  const finish = result => {
    if (finished) return;
    finished = true;
    observer?.disconnect();
    resize?.disconnect();
    for (const image of watchedImages) {
      image.removeEventListener('load', check);
      image.removeEventListener('error', check);
    }
    watchedImages.clear();
    clearTimeout(timer);
    for (const event of events) window.removeEventListener(event, check, true);
    document.fonts?.removeEventListener('loadingdone', check);
    delete globalThis[key];
    const emit = globalThis[binding];
    if (typeof emit === 'function') emit(JSON.stringify(result));
  };
  const check = () => {
    if (document.readyState === 'loading') return;
    let candidates;
    try {
      candidates = [...document.querySelectorAll(selector)];
    } catch (error) {
      finish({ ready: false, reason: error?.name === 'SyntaxError' ? 'invalid_selector' : 'observer_error',
        error: String(error) });
      return;
    }
    try {
      for (const element of candidates) resize?.observe(element);
      const matches = candidates.filter(visible);
      const images = matches.flatMap(el => el.tagName === 'IMG' ? [el] : [...(el.querySelectorAll?.('img') || [])]);
      const relevant = images.filter(img => visible(img) && img.getBoundingClientRect().top < window.innerHeight &&
        img.getBoundingClientRect().bottom > 0);
      for (const image of relevant) if (!watchedImages.has(image)) {
        watchedImages.add(image);
        image.addEventListener('load', check);
        image.addEventListener('error', check);
      }
      last = { visible_matches: matches.length, pending_images: relevant.filter(img => !img.complete).length,
        failed_images: relevant.filter(img => img.complete && img.naturalWidth === 0).length,
        fonts_loading: document.fonts?.status === 'loading' };
      if (matches.length && !last.pending_images && !last.fonts_loading)
        finish({ ready: true, selector, ...last, document_state: document.readyState });
    } catch (error) {
      finish({ ready: false, reason: 'observer_error', error: String(error) });
    }
  };
  Object.defineProperty(globalThis, key, { configurable: true,
    value: { cancel: () => finish({ ready: false, reason: 'cancelled' }), inspect: () => ({...last}) } });
  observer = new MutationObserver(check);
  if (typeof ResizeObserver === 'function') resize = new ResizeObserver(check);
  observer.observe(document, { subtree: true, childList: true, attributes: true, characterData: true });
  for (const event of events) window.addEventListener(event, check, true);
  document.fonts?.addEventListener('loadingdone', check);
  timer = setTimeout(() => finish({ ready: false, reason: 'business_deadline', ...last }), timeoutMs);
  check();
  return { watching: !finished };
})(...__ARGS__)
