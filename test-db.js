const { Pool } = require('pg');

const pool = new Pool({
    connectionString: 'postgres://neondb_owner:npg_VguXJD7ZUp1A@ep-rough-king-a553d6kn-pooler.us-east-2.aws.neon.tech/neondb?sslmode=require',
    ssl: { rejectUnauthorized: false }
});

(async () => {
    try {
        const client = await pool.connect();
        console.log('Connected to PostgreSQL database.');
        const { rows } = await client.query('SELECT NOW()');
        console.log('Current time:', rows[0].now);
        client.release();
    } catch (err) {
        console.error('Connection failed:', err.message);
    } finally {
        await pool.end();
    }
})();