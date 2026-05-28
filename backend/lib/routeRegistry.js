/** @type {string[]} */
const registeredRouteModules = [];

/**
 * Record a route module mounted at startup (guards against silent registration loss).
 * @param {string} name
 */
export function registerRouteModule(name) {
  const key = String(name || '').trim();
  if (!key || registeredRouteModules.includes(key)) return;
  registeredRouteModules.push(key);
}

export function getRegisteredRouteModules() {
  return [...registeredRouteModules];
}

export function logRegisteredRouteModules() {
  const modules = getRegisteredRouteModules();
  console.log(`[routes] registered modules (${modules.length}): ${modules.join(', ')}`);
}
