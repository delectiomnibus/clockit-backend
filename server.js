const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const app = express();

// Initialize SQLite database
const db = new sqlite3.Database('./clockit.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        // Create employees table
        db.run(`CREATE TABLE IF NOT EXISTS employees (
            employee_id TEXT PRIMARY KEY,
            name TEXT NOT NULL
        )`);
        // Create punches table with notes and updated_by columns
        db.run(`CREATE TABLE IF NOT EXISTS punches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT,
            type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            updated_by TEXT,
            notes TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
        )`);
        // Create users table
        db.run(`CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('Admin', 'Employee')),
            employee_id TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
        )`);
    }
});

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
}));

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session.user) {
        return next();
    }
    res.status(401).json({ error: 'Unauthorized. Please log in.' });
}

// Middleware to check if user is an Admin
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'Admin') {
        return next();
    }
    res.status(403).json({ error: 'Forbidden. Admin access required.' });
}

// Login endpoint
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Database error.' });
        }
        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: 'Invalid username or password.' });
        }

        req.session.user = { username: user.username, role: user.role, employee_id: user.employee_id };
        res.json({ message: 'Login successful.', role: user.role });
    });
});

// Logout endpoint
app.post('/logout', (req, res) => {
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
    if (req.session.user) {
        res.json({ loggedIn: true, username: req.session.user.username, role: req.session.user.role, employee_id: req.session.user.employee_id });
    } else {
        res.json({ loggedIn: false });
    }
});

// Register endpoint (for creating initial Admin user)
app.post('/register', async (req, res) => {
    const { username, password, role, employee_id } = req.body;
    if (!username || !password || !role) {
        return res.status(400).json({ error: 'Username, password, and role are required.' });
    }
    if (role !== 'Admin' && role !== 'Employee') {
        return res.status(400).json({ error: 'Role must be Admin or Employee.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password, role, employee_id) VALUES (?, ?, ?, ?)',
        [username, hashedPassword, role, employee_id || null],
        function (err) {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Failed to register user.' });
            }
            res.json({ message: 'User registered successfully.' });
        }
    );
});

// Protect existing endpoints with authentication
app.get('/employees', isAuthenticated, isAdmin, (req, res) => {
    db.all('SELECT * FROM employees', [], (err, rows) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Failed to fetch employees' });
            return;
        }
        res.json({ employees: rows });
    });
});

app.post('/employees', isAuthenticated, isAdmin, (req, res) => {
    const { name, employee_id } = req.body;
    if (!name || !employee_id) {
        res.status(400).json({ error: 'Name and employee ID are required' });
        return;
    }
    db.run('INSERT INTO employees (employee_id, name) VALUES (?, ?)', [employee_id, name], function (err) {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Failed to add employee' });
            return;
        }
        res.json({ message: 'Employee added successfully' });
    });
});

app.put('/employees/:employee_id', isAuthenticated, isAdmin, (req, res) => {
    const employeeId = req.params.employee_id;
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Name is required' });
    }

    db.run('UPDATE employees SET name = ? WHERE employee_id = ?', [name, employeeId], function (err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Failed to update employee' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Employee not found' });
        }
        res.json({ message: 'Employee updated successfully' });
    });
});

app.delete('/employees/:employee_id', isAuthenticated, isAdmin, (req, res) => {
    const employeeId = req.params.employee_id;
    db.run('DELETE FROM employees WHERE employee_id = ?', [employeeId], function (err) {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Failed to delete employee' });
            return;
        }
        if (this.changes === 0) {
            res.status(404).json({ error: 'Employee not found' });
            return;
        }
        db.run('DELETE FROM punches WHERE employee_id = ?', [employeeId], function (err) {
            if (err) {
                console.error(err);
            }
        });
        res.json({ message: 'Employee deleted successfully' });
    });
});

app.post('/admin-punch', isAuthenticated, isAdmin, (req, res) => {
    const { employee_id } = req.body;
    if (!employee_id) {
        res.status(400).json({ error: 'Employee ID is required' });
        return;
    }

    db.get('SELECT * FROM punches WHERE employee_id = ? ORDER BY timestamp DESC LIMIT 1', [employee_id], (err, lastPunch) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Failed to fetch punch data' });
            return;
        }

        const type = lastPunch && lastPunch.type === 'in' ? 'out' : 'in';
        const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');

        db.run('INSERT INTO punches (employee_id, type, timestamp, updated_by, notes) VALUES (?, ?, ?, ?, ?)', [employee_id, type, timestamp, req.session.user.username, null], function (err) {
            if (err) {
                console.error(err);
                res.status(500).json({ error: 'Failed to record punch' });
                return;
            }
            res.json({ message: `Successfully punched ${type}`, last_punch_id: this.lastID });
        });
    });
});

// Employee punch (clock in/out)
app.post('/employee-punch', isAuthenticated, (req, res) => {
    const user = req.session.user;
    if (user.role !== 'Employee') {
        return res.status(403).json({ error: 'Only employees can clock in/out.' });
    }

    const employee_id = user.employee_id;
    if (!employee_id) {
        return res.status(400).json({ error: 'Employee ID not associated with this user.' });
    }

    db.get('SELECT * FROM punches WHERE employee_id = ? ORDER BY timestamp DESC LIMIT 1', [employee_id], (err, lastPunch) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Failed to fetch punch data' });
        }

        const type = lastPunch && lastPunch.type === 'in' ? 'out' : 'in';
        const timestamp = new Date().toISOString().slice(0, 19).replace('T', ' ');

        db.run('INSERT INTO punches (employee_id, type, timestamp, updated_by, notes) VALUES (?, ?, ?, ?, ?)', [employee_id, type, timestamp, null, null], function (err) {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Failed to record punch' });
            }
            res.json({ message: `Successfully punched ${type}`, last_punch_id: this.lastID });
        });
    });
});

// Update notes for a punch
app.put('/punch/:id/notes', isAuthenticated, (req, res) => {
    const punchId = req.params.id;
    const { notes } = req.body;
    if (!notes) {
        return res.status(400).json({ error: 'Notes are required' });
    }

    db.run('UPDATE punches SET notes = ? WHERE id = ?', [notes, punchId], function (err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Failed to update notes' });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'Punch not found' });
        }
        res.json({ message: 'Notes updated successfully' });
    });
});

// Get user associated with an employee
app.get('/user-for-employee/:employee_id', isAuthenticated, isAdmin, (req, res) => {
    const employeeId = req.params.employee_id;
    db.get('SELECT username FROM users WHERE employee_id = ?', [employeeId], (err, user) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Failed to fetch user' });
        }
        res.json({ user });
    });
});

// Create or update user for an employee
app.post('/user-for-employee/:employee_id', isAuthenticated, isAdmin, async (req, res) => {
    const employeeId = req.params.employee_id;
    const { username, password } = req.body;

    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }

    // Check if employee exists
    db.get('SELECT * FROM employees WHERE employee_id = ?', [employeeId], (err, employee) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Failed to fetch employee' });
        }
        if (!employee) {
            return res.status(404).json({ error: 'Employee not found' });
        }

        // Check if username is already taken by another user
        db.get('SELECT * FROM users WHERE username = ? AND employee_id != ?', [username, employeeId], async (err, existingUser) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'Database error' });
            }
            if (existingUser) {
                return res.status(400).json({ error: 'Username already taken by another user' });
            }

            // Check if a user already exists for this employee
            db.get('SELECT * FROM users WHERE employee_id = ?', [employeeId], async (err, user) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ error: 'Failed to fetch user' });
                }

                if (user) {
                    // Update existing user
                    const updates = [];
                    const params = [];
                    if (username !== user.username) {
                        updates.push('username = ?');
                        params.push(username);
                    }
                    if (password) {
                        const hashedPassword = await bcrypt.hash(password, 10);
                        updates.push('password = ?');
                        params.push(hashedPassword);
                    }
                    if (updates.length === 0) {
                        return res.json({ message: 'No changes to update' });
                    }
                    params.push(user.username);

                    db.run(`UPDATE users SET ${updates.join(', ')} WHERE username = ?`, params, function (err) {
                        if (err) {
                            console.error(err);
                            return res.status(500).json({ error: 'Failed to update user' });
                        }
                        res.json({ message: 'User updated successfully' });
                    });
                } else {
                    // Create new user
                    if (!password) {
                        return res.status(400).json({ error: 'Password is required to create a new user' });
                    }
                    const hashedPassword = await bcrypt.hash(password, 10);
                    db.run('INSERT INTO users (username, password, role, employee_id) VALUES (?, ?, ?, ?)',
                        [username, hashedPassword, 'Employee', employeeId],
                        function (err) {
                            if (err) {
                                console.error(err);
                                return res.status(500).json({ error: 'Failed to create user' });
                            }
                            res.json({ message: 'User created successfully' });
                        }
                    );
                }
            });
        });
    });
});

app.get('/currently-punched-in', isAuthenticated, (req, res) => {
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
    db.all(query, [], (err, rows) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Failed to fetch punched-in employees' });
            return;
        }
        res.json({ employees: rows });
    });
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

app.get('/time-cards', isAuthenticated, (req, res) => {
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
        WHERE p.timestamp BETWEEN ? AND ?
        ORDER BY e.employee_id, p.timestamp
    `;

    db.all(query, [periodStart.toISOString(), periodEnd.toISOString()], (err, rows) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Failed to fetch time cards' });
        }

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
    });
});

app.get('/timecard/:employee_id', isAuthenticated, (req, res) => {
    const employeeId = req.params.employee_id;
    const user = req.session.user;

    // Allow Admins to view any timecard, Employees to view only their own
    if (user.role !== 'Admin' && user.employee_id !== employeeId) {
        return res.status(403).json({ error: 'Forbidden. You can only view your own time card.' });
    }

    db.get('SELECT * FROM employees WHERE employee_id = ?', [employeeId], (err, employee) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Failed to fetch employee' });
            return;
        }
        if (!employee) {
            res.status(404).json({ error: 'Employee not found' });
            return;
        }

        db.all('SELECT * FROM punches WHERE employee_id = ? ORDER BY timestamp', [employeeId], (err, punches) => {
            if (err) {
                console.error(err);
                res.status(500).json({ error: 'Failed to fetch punches' });
                return;
            }
            res.json({ employee, punches });
        });
    });
});

app.put('/punch/:id', isAuthenticated, isAdmin, (req, res) => {
    const punchId = req.params.id;
    const { timestamp, notes } = req.body;
    const updates = [];
    const params = [];
    if (timestamp) {
        updates.push('timestamp = ?');
        params.push(timestamp);
    }
    if (notes) {
        updates.push('notes = ?');
        params.push(notes);
    }
    if (updates.length === 0) {
        return res.status(400).json({ error: 'No updates provided' });
    }
    params.push(punchId);

    db.run(`UPDATE punches SET ${updates.join(', ')}, updated_by = ? WHERE id = ?`, [...params, req.session.user.username], function (err) {
        if (err) {
            console.error(err);
            res.status(500).json({ error: 'Failed to update punch' });
            return;
        }
        if (this.changes === 0) {
            res.status(404).json({ error: 'Punch not found' });
            return;
        }
        res.json({ message: 'Punch updated successfully' });
    });
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});