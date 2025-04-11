require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const PGSession = require('connect-pg-simple')(session);
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();

// Apply CORS middleware first
app.use(cors({
    origin: ['http://localhost:8080', 'http://127.0.0.1:8080', 'https://clockit-frontend.vercel.app'],
    credentials: true,
    methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
console.log('CORS middleware applied');

// Explicitly handle OPTIONS requests
app.options('*', (req, res) => {
    console.log('Handling OPTIONS request for:', req.path);
    res.status(200).send();
});

// Initialize PostgreSQL connection pool
console.log('POSTGRES_URL:', process.env.POSTGRES_URL ? 'Set' : 'Not set');
const pool = new Pool({
    connectionString: process.env.POSTGRES_URL,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 30000,
    idleTimeoutMillis: 30000,
    max: 5
});

pool.on('error', (err, client) => {
    console.error('Unexpected error on idle client:', err);
});

// Retry logic for database connection
const retry = async (fn, retries = 3, delay = 5000) => {
    for (let i = 0; i < retries; i++) {
        try {
            return await fn();
        } catch (err) {
            console.error(`Connection attempt ${i + 1}/${retries} failed:`, err.message);
            if (i === retries - 1) throw err;
            console.log(`Retrying connection (${i + 1}/${retries})...`);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
};

// Test the database connection and set up the session table
let dbConnected = false;
(async () => {
    try {
        await retry(async () => {
            const client = await pool.connect();
            try {
                console.log('Connected to PostgreSQL database.');
                await client.query(`
                    CREATE TABLE IF NOT EXISTS session (
                        sid VARCHAR NOT NULL COLLATE "default",
                        sess JSON NOT NULL,
                        expire TIMESTAMP(6) NOT NULL,
                        PRIMARY KEY (sid)
                    );
                `);
                console.log('Session table created or already exists.');
                dbConnected = true;
            } catch (err) {
                console.error('Error setting up session table:', err.message);
                throw err;
            } finally {
                client.release();
            }
        });
    } catch (err) {
        console.error('Failed to connect to database after retries:', err.message);
        dbConnected = false;
    }
})();

// Other middleware
app.use(express.json());
app.use(cookieParser());

// Only set up session middleware if database connection succeeded
if (dbConnected) {
    const sessionSecret = process.env.SESSION_SECRET || 'your-secret-key';
    console.log('Using SESSION_SECRET:', sessionSecret);
    app.use(session({
        store: new PGSession({
            pool: pool,
            tableName: 'session'
        }),
        secret: sessionSecret,
        resave: false,
        saveUninitialized: false,
        cookie: { 
            secure: true,
            sameSite: 'none',
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        }
    }));
    console.log('Session middleware configured with Postgres store');
} else {
    console.error('Session middleware not configured: Database connection failed.');
}

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    if (!dbConnected) {
        return res.status(503).json({ error: 'Service unavailable: Database connection failed.' });
    }
    if (req.session.user) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized. Please log in.' });
}

// Middleware to check if user is an Admin
function isAdmin(req, res, next) {
    if (!dbConnected) {
        return res.status(503).json({ error: 'Service unavailable: Database connection failed.' });
    }
    if (req.session.user && req.session.user.role === 'Admin') {
        return next();
    }
    res.status(403).json({ error: 'Forbidden. Admin access required.' });
}

// Login endpoint with debugging
app.post('/login', async (req, res) => {
    if (!dbConnected) {
        return res.status(503).json({ error: 'Service unavailable: Database connection failed.' });
    }
    const { username, password } = req.body;
    console.log('Login attempt for username:', username);
    try {
        const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (rows.length === 0) {
            console.log('User not found:', username);
            return res.status(401).json({ error: 'User not found.' });
        }
        const user = rows[0];
        console.log('User found:', user);
        const match = await bcrypt.compare(password, user.password);
        console.log('Comparing password:', password, 'against hash:', user.password);
        console.log('Password match result:', match);
        if (!match) {
            return res.status(401).json({ error: 'Invalid password.' });
        }
        req.session.user = { username: user.username, role: user.role, employee_id: user.employee_id };
        console.log('Session after setting user:', req.session);
        req.session.save((err) => {
            if (err) {
                console.error('Error saving session:', err);
                return res.status(500).json({ error: 'Error saving session.' });
            }
            console.log('Session saved successfully');
            console.log('Session ID after save:', req.sessionID);
            console.log('Set-Cookie header should be set with:', `connect.sid=s%3A${req.sessionID}`);
            res.json({ role: user.role });
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error logging in.' });
    }
});

// Logout endpoint
app.post('/logout', (req, res) => {
    if (!dbConnected) {
        return res.status(503).json({ error: 'Service unavailable: Database connection failed.' });
    }
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Failed to log out.' });
        }
        res.json({ message: 'Logout successful.' });
    });
});

// Get current user (for frontend to check login status)
app.get('/current-user', (req, res) => {
    if (!dbConnected) {
        return res.status(503).json({ error: 'Service unavailable: Database connection failed.' });
    }
    console.log('Received /current-user request');
    console.log('Session ID (sid):', req.sessionID);
    console.log('Session data:', req.session);
    if (req.session.user) {
        console.log('User is logged in:', req.session.user);
        res.json({ loggedIn: true, username: req.session.user.username, role: req.session.user.role, employee_id: req.session.user.employee_id });
    } else {
        console.log('No user in session, user is not logged in');
        res.json({ loggedIn: false });
    }
});

// For testing connection
app.get('/test-db', async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT NOW()');
        res.json({ time: rows[0].now });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Register endpoint (for creating initial Admin user)
app.post('/register', async (req, res) => {
    if (!dbConnected) {
        return res.status(503).json({ error: 'Service unavailable: Database connection failed.' });
    }
    const { username, password, role, employee_id } = req.body;
    if (!username || !password || !role) {
        return res.status(400).json({ error: 'Username, password, and role are required.' });
    }
    if (role !== 'Admin' && role !== 'Employee') {
        return res.status(400).json({ error: 'Role must be Admin or Employee.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (username, password, role, employee_id) VALUES ($1, $2, $3, $4)',
            [username, hashedPassword, role, employee_id || null]
        );
        res.json({ message: 'User registered successfully.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to register user.' });
    }
});

// Protect existing endpoints with authentication
app.get('/employees', isAuthenticated, isAdmin, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT * FROM employees');
        res.json({ employees: rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch employees' });
    }
});

app.post('/employees', isAuthenticated, isAdmin, async (req, res) => {
    const { name, employee_id } = req.body;
    if (!name || !employee_id) {
        return res.status(400).json({ error: 'Name and employee ID are required' });
    }
    try {
        await pool.query('INSERT INTO employees (employee_id, name) VALUES ($1, $2)', [employee_id, name]);
        res.json({ message: 'Employee added successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to add employee' });
    }
});

app.put('/employees/:employee_id', isAuthenticated, isAdmin, async (req, res) => {
    const employeeId = req.params.employee_id;
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Name is required' });
    }

    try {
        const result = await pool.query('UPDATE employees SET name = $1 WHERE employee_id = $2', [name, employeeId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Employee not found' });
        }
        res.json({ message: 'Employee updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update employee' });
    }
});

app.delete('/employees/:employee_id', isAuthenticated, isAdmin, async (req, res) => {
    const employeeId = req.params.employee_id;
    try {
        const result = await pool.query('DELETE FROM employees WHERE employee_id = $1', [employeeId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Employee not found' });
        }
        await pool.query('DELETE FROM punches WHERE employee_id = $1', [employeeId]);
        res.json({ message: 'Employee deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete employee' });
    }
});

app.post('/admin-punch', isAuthenticated, isAdmin, async (req, res) => {
    const { employee_id } = req.body;
    if (!employee_id) {
        return res.status(400).json({ error: 'Employee ID is required' });
    }

    try {
        const { rows } = await pool.query('SELECT * FROM punches WHERE employee_id = $1 ORDER BY timestamp DESC LIMIT 1', [employee_id]);
        const lastPunch = rows[0];

        const type = lastPunch && lastPunch.type === 'in' ? 'out' : 'in';
        const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');

        const result = await pool.query(
            'INSERT INTO punches (employee_id, type, timestamp, updated_by, notes) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [employee_id, type, timestamp, req.session.user.username, null]
        );
        res.json({ message: `Successfully punched ${type}`, last_punch_id: result.rows[0].id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to record punch' });
    }
});

// Employee punch (clock in/out)
app.post('/employee-punch', isAuthenticated, async (req, res) => {
    const user = req.session.user;
    if (user.role !== 'Employee') {
        return res.status(403).json({ error: 'Only employees can clock in/out.' });
    }

    const employee_id = user.employee_id;
    if (!employee_id) {
        return res.status(400).json({ error: 'Employee ID not associated with this user.' });
    }

    try {
        const { rows } = await pool.query('SELECT * FROM punches WHERE employee_id = $1 ORDER BY timestamp DESC LIMIT 1', [employee_id]);
        const lastPunch = rows[0];

        const type = lastPunch && lastPunch.type === 'in' ? 'out' : 'in';
        const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');

        const result = await pool.query(
            'INSERT INTO punches (employee_id, type, timestamp, updated_by, notes) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [employee_id, type, timestamp, null, null]
        );
        res.json({ message: `Successfully punched ${type}`, last_punch_id: result.rows[0].id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to record punch' });
    }
});

// Update notes for a punch
app.put('/punch/:id/notes', isAuthenticated, async (req, res) => {
    const punchId = req.params.id;
    const { notes } = req.body;
    if (!notes) {
        return res.status(400).json({ error: 'Notes are required' });
    }

    try {
        const result = await pool.query('UPDATE punches SET notes = $1 WHERE id = $2', [notes, punchId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Punch not found' });
        }
        res.json({ message: 'Notes updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update notes' });
    }
});

// Get user associated with an employee
app.get('/user-for-employee/:employee_id', isAuthenticated, isAdmin, async (req, res) => {
    const employeeId = req.params.employee_id;
    try {
        const { rows } = await pool.query('SELECT username FROM users WHERE employee_id = $1', [employeeId]);
        res.json({ user: rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

// Create or update user for an employee
app.post('/user-for-employee/:employee_id', isAuthenticated, isAdmin, async (req, res) => {
    const employeeId = req.params.employee_id;
    const { username, password } = req.body;

    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }

    try {
        const { rows: employeeRows } = await pool.query('SELECT * FROM employees WHERE employee_id = $1', [employeeId]);
        const employee = employeeRows[0];
        if (!employee) {
            return res.status(404).json({ error: 'Employee not found' });
        }

        const { rows: existingUserRows } = await pool.query('SELECT * FROM users WHERE username = $1 AND employee_id != $2', [username, employeeId]);
        if (existingUserRows.length > 0) {
            return res.status(400).json({ error: 'Username already taken by another user' });
        }

        const { rows: userRows } = await pool.query('SELECT * FROM users WHERE employee_id = $1', [employeeId]);
        const user = userRows[0];

        if (user) {
            // Update existing user
            const updates = [];
            const params = [];
            if (username !== user.username) {
                updates.push('username = $1');
                params.push(username);
            }
            if (password) {
                const hashedPassword = await bcrypt.hash(password, 10);
                updates.push('password = $2');
                params.push(hashedPassword);
            }
            if (updates.length === 0) {
                return res.json({ message: 'No changes to update' });
            }
            params.push(user.username);

            await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE username = $${params.length}`, params);
            res.json({ message: 'User updated successfully' });
        } else {
            // Create new user
            if (!password) {
                return res.status(400).json({ error: 'Password is required to create a new user' });
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            await pool.query(
                'INSERT INTO users (username, password, role, employee_id) VALUES ($1, $2, $3, $4)',
                [username, hashedPassword, 'Employee', employeeId]
            );
            res.json({ message: 'User created successfully' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create/update user' });
    }
});

app.get('/currently-punched-in', isAuthenticated, async (req, res) => {
    const query = `
        SELECT e.employee_id, e.name, p.type, p.timestamp AS punched_in_at, p.id AS last_punch_id
        FROM employees e
        JOIN punches p ON e.employee_id = p.employee_id
        WHERE p.id IN (
            SELECT MAX(id)
            FROM punches
            WHERE employee_id = e.employee_id
            GROUP BY employee_id
        ) AND p.type = 'in'
    `;
    try {
        const { rows } = await pool.query(query);
        res.json({ employees: rows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch punched-in employees' });
    }
});

app.get('/pay-periods', isAuthenticated, (req, res) => {
    const payPeriods = [];
    const today = new Date();
    const startOfYear = new Date(today.getFullYear(), 0, 1);

    let currentStart = new Date(startOfYear);
    if (currentStart.getDay() !== 1) {
        currentStart.setDate(currentStart.getDate() + (1 - currentStart.getDay() + 7) % 7);
    }

    while (currentStart <= today) {
        const periodEnd = new Date(currentStart);
        periodEnd.setDate(periodEnd.getDate() + 13);
        if (periodEnd > today) {
            periodEnd.setDate(today.getDate());
        }
        const startStr = currentStart.toISOString().split('T')[0];
        const endStr = periodEnd.toISOString().split('T')[0];
        payPeriods.push({ start_date: startStr, end_date: endStr });
        currentStart.setDate(currentStart.getDate() + 14);
    }

    res.json({ pay_periods: payPeriods.reverse() });
});

app.get('/time-cards', isAuthenticated, async (req, res) => {
    const payPeriod = req.query.pay_period;
    if (!payPeriod) {
        return res.status(400).json({ error: 'Pay period is required' });
    }

    const periodStart = new Date(`${payPeriod}T00:00:00.000Z`);
    const periodEnd = new Date(periodStart);
    periodEnd.setDate(periodStart.getDate() + 14);
    periodEnd.setHours(23, 59, 59, 999);

    const query = `
        SELECT e.employee_id, e.name, p.id, p.type, p.timestamp
        FROM employees e
        LEFT JOIN punches p ON e.employee_id = p.employee_id
        WHERE p.timestamp BETWEEN $1 AND $2
        ORDER BY e.employee_id, p.timestamp
    `;

    try {
        const { rows } = await pool.query(query, [periodStart.toISOString(), periodEnd.toISOString()]);
        const timeCards = [];
        let currentEmployee = null;
        let currentIn = null;

        rows.forEach(row => {
            if (!row.id) return;

            if (!currentEmployee || currentEmployee.employee_id !== row.employee_id) {
                if (currentEmployee && currentEmployee.total_hours > 0) {
                    timeCards.push(currentEmployee);
                }
                currentEmployee = {
                    employee_id: row.employee_id,
                    name: row.name,
                    total_hours: 0
                };
                currentIn = null;
            }

            const punchTime = new Date(row.timestamp.replace(" ", "T") + ".000Z");
            if (row.type === 'in') {
                currentIn = punchTime;
            } else if (row.type === 'out' && currentIn) {
                const punchOut = punchTime;
                const hours = (punchOut - currentIn) / (1000 * 60 * 60);
                if (hours >= 0) {
                    currentEmployee.total_hours += hours;
                }
                currentIn = null;
            }
        });

        if (currentEmployee && currentEmployee.total_hours > 0) {
            timeCards.push(currentEmployee);
        }

        timeCards.forEach(card => {
            card.total_hours = parseFloat(card.total_hours.toFixed(2));
        });

        res.json({ timeCards });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch time cards' });
    }
});

app.get('/timecard/:employee_id', isAuthenticated, async (req, res) => {
    const employeeId = req.params.employee_id;
    const user = req.session.user;

    if (user.role !== 'Admin' && user.employee_id !== employeeId) {
        return res.status(403).json({ error: 'Forbidden. You can only view your own time card.' });
    }

    try {
        const { rows: employeeRows } = await pool.query('SELECT * FROM employees WHERE employee_id = $1', [employeeId]);
        const employee = employeeRows[0];
        if (!employee) {
            return res.status(404).json({ error: 'Employee not found' });
        }

        const { rows: punches } = await pool.query('SELECT * FROM punches WHERE employee_id = $1 ORDER BY timestamp', [employeeId]);
        res.json({ employee, punches });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch punches' });
    }
});

app.put('/punch/:id', isAuthenticated, isAdmin, async (req, res) => {
    const punchId = req.params.id;
    const { timestamp, notes } = req.body;
    const updates = [];
    const params = [];
    if (timestamp) {
        updates.push('timestamp = $1');
        params.push(timestamp);
    }
    if (notes) {
        updates.push('notes = $2');
        params.push(notes);
    }
    if (updates.length === 0) {
        return res.status(400).json({ error: 'No updates provided' });
    }
    params.push(punchId);

    try {
        const result = await pool.query(
            `UPDATE punches SET ${updates.join(', ')}, updated_by = $${params.length + 1} WHERE id = $${params.length + 2}`,
            [...params, req.session.user.username, punchId]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Punch not found' });
        }
        res.json({ message: 'Punch updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update punch' });
    }
});

// Test hash endpoint
app.post('/test-hash', async (req, res) => {
    const { password } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        const match = await bcrypt.compare(password, hash);
        res.json({ hash, match });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error testing hash.' });
    }
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});