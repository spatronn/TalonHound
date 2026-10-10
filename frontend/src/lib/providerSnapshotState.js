/**
 * Provider snapshot bookkeeping for the Intelligence tab.
 *
 * Enrichment cards report a small snapshot from a useEffect that depends on
 * their `onSnapshot` prop. The parent must therefore (1) hand each card a
 * referentially stable callback and (2) skip the state update when the
 * snapshot is unchanged — otherwise every report re-renders the parent, which
 * re-runs the card effect, which reports again: an endless render loop.
 */

function sameValue(a, b) {
  if (Object.is(a, b)) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => Object.prototype.hasOwnProperty.call(b, k) && sameValue(a[k], b[k]));
}

export function snapshotsEqual(a, b) {
  return sameValue(a, b);
}

/** Returns `prev` itself when nothing changed, so React bails out of the re-render. */
export function mergeProviderSnapshot(prev, provider, snapshot) {
  const current = prev || {};
  if (snapshotsEqual(current[provider], snapshot)) return current;
  return { ...current, [provider]: snapshot };
}

/**
 * Build a cache of stable per-provider callbacks around a state setter.
 * `handlerFor('virustotal')` always returns the same function for a given setter.
 */
export function createSnapshotHandlerCache(setSnapshots) {
  const cache = new Map();
  return function handlerFor(provider) {
    let handler = cache.get(provider);
    if (!handler) {
      handler = (snapshot) => setSnapshots((prev) => mergeProviderSnapshot(prev, provider, snapshot));
      cache.set(provider, handler);
    }
    return handler;
  };
}
