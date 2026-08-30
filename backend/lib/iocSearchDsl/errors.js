// A single typed error for every DSL validation failure. Carries a machine-readable
// `code` plus an analyst-facing `message` (field/operator level where possible), and
// optionally the 0-based character `position` of the offending token so the frontend
// can point at it.
export class DslError extends Error {
  constructor(message, { code = 'invalid_query', position = null, field = null } = {}) {
    super(message);
    this.name = 'DslError';
    this.code = code;
    this.position = position;
    this.field = field;
  }

  toJSON() {
    return {
      code: this.code,
      message: this.message,
      ...(this.position != null ? { position: this.position } : {}),
      ...(this.field != null ? { field: this.field } : {})
    };
  }
}

export function isDslError(err) {
  return err instanceof DslError;
}
