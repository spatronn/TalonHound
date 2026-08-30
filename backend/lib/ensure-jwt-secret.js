const raw = process.env.JWT_SECRET;
const s = raw == null ? '' : String(raw).trim();

if (!s) {
  throw new Error(
    'JWT_SECRET is required (non-empty). Set it in .env — e.g. openssl rand -hex 32 — see .env.example.'
  );
}

const norm = s.toLowerCase().replace(/[\s_-]+/g, '');
if (
  norm === 'changeme' ||
  norm === 'required' ||
  norm === 'devinsecurejwtsecret' ||
  norm === 'yoursecrethere' ||
  norm === 'replaceme' ||
  norm === 'placeholder'
) {
  throw new Error(
    'JWT_SECRET must be a strong random value, not a placeholder (replace values like CHANGE_ME).'
  );
}

if (s.length < 32) {
  throw new Error(
    'JWT_SECRET must be at least 32 characters. Generate with: openssl rand -hex 32'
  );
}
