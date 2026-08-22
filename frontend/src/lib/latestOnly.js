// Guard that lets only the most-recently-started async operation apply its
// result. Each call to next() registers a new "latest" operation and returns an
// isStale() predicate; every earlier operation's predicate then reports true, so
// a slow/old response (including a failed one) can never overwrite a newer one.
//
// Used by the Feeds page load: a transient first request that resolves late —
// after the user hit Refresh or the effect re-ran — must not clobber the good
// state the newer load already produced.
export function createLatestOnly() {
  let current = 0;
  return {
    next() {
      current += 1;
      const token = current;
      return () => token !== current;
    }
  };
}
