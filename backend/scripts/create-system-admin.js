import '../lib/ensure-db-password.js';
import pg from 'pg';
import { provisionSystemAdmin, SYSTEM_ADMIN_EMAIL } from '../lib/systemAdminBootstrap.js';
import { generateTemporaryPassword } from '../lib/temporaryPassword.js';

/**
 * Secure operator flow for creating (or reconciling) the protected system administrator.
 *
 * Usage:
 *   docker compose exec backend npm run create-system-admin
 *   # or, to choose the initial password yourself instead of a generated one:
 *   docker compose exec -e SYSTEM_ADMIN_PASSWORD='...' backend npm run create-system-admin
 *
 * When the account is missing it is created with must_change_password = TRUE. The initial password
 * comes from SYSTEM_ADMIN_PASSWORD if set; otherwise a strong random password is generated and
 * printed ONCE to this terminal (the operator's secure reveal channel — it is never written to the
 * application logs). When the account already exists it is only re-flagged/role-reconciled; the
 * existing password and profile are preserved.
 */

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || 'db',
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || 'talonhound',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'talonhound'
});

// Log wrapper that only ever emits non-secret status lines.
const logger = { info: (msg) => console.log(msg) };

async function main() {
  const provided = process.env.SYSTEM_ADMIN_PASSWORD;
  const generated = !provided;
  const password = provided || generateTemporaryPassword();

  const result = await provisionSystemAdmin(pool, { password, logger });

  if (result.status === 'created') {
    console.log(`\nCreated protected system administrator: ${SYSTEM_ADMIN_EMAIL}`);
    console.log('The account must change its password at first login.');
    if (generated) {
      console.log('\n  Generated initial password (shown once — store it securely now):');
      console.log(`\n      ${password}\n`);
    } else {
      console.log('Initial password set from SYSTEM_ADMIN_PASSWORD.');
    }
  } else {
    console.log(`\nReconciled existing account as protected system administrator: ${SYSTEM_ADMIN_EMAIL}`);
    console.log('Existing password and profile were preserved.');
  }
}

main()
  .then(() => pool.end())
  .catch(async (err) => {
    console.error('[create-system-admin] failed:', err?.message || err);
    await pool.end().catch(() => {});
    process.exit(1);
  });
