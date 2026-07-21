/** Build the JSON body for POST /integrations/:key/run-now. */
export function buildIntegrationRunNowPayload(key, runMode) {
  if (key === 'usom-trcert') {
    return { run_mode: runMode };
  }
  return {};
}
