const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');

// Secret key (make sure to store it in .env)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

const app = express();
const port = process.env.PORT || 3000;

// Middleware for parsing incoming requests
app.use(bodyParser.json());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Public route: Login (does not require authentication)
app.post('/login', [
  body('email').isEmail().withMessage('Please enter a valid email address'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;

  try {
    // Fetch the user by email
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Compare the entered password with the hashed password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

    // Send token to client
    res.status(200).json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// JWT Middleware to verify tokens
function authenticateToken(req, res, next) {
  const token = req.header('Authorization')?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied, token missing' });

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next(); // Pass control to the next handler
  } catch (err) {
    res.status(400).json({ error: 'Invalid token' });
  }
}

// Apply the JWT middleware to protect all routes below (excluding login)
app.use(authenticateToken);

// Protected route: Test route
app.get('/', (req, res) => {
  res.send('Welcome to the protected PoC Tracker API!');
});

// Protected route: Get all users
app.get('/users', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users');
    res.status(200).json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route: Create a new user
app.post('/users', [
  body('email').isEmail().withMessage('Please enter a valid email address'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  body('first_name').notEmpty().withMessage('First name is required'),
  body('last_name').notEmpty().withMessage('Last name is required'),
  body('role').optional().isIn(['user', 'admin']).withMessage('Role must be either user or admin')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password, first_name, last_name, role } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, first_name, last_name, role) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [email, hashedPassword, first_name, last_name, role]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route: Get all PoCs
app.get('/pocs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM pocs');
    res.status(200).json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route: Create a new PoC
app.post('/pocs', [
  body('poc_name').notEmpty().withMessage('PoC name is required'),
  body('customer_name').notEmpty().withMessage('Customer name is required'),
  body('start_date').optional().isISO8601().withMessage('Start date must be a valid date'),
  body('end_date').optional().isISO8601().withMessage('End date must be a valid date'),
  body('status').isIn(['ongoing', 'completed']).withMessage('Status must be ongoing or completed')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { poc_name, customer_name, start_date, end_date, status } = req.body;

  try {
    const result = await pool.query(
      'INSERT INTO pocs (poc_name, customer_name, start_date, end_date, status) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [poc_name, customer_name, start_date, end_date, status]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route: Get a specific PoC by ID
app.get('/pocs/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('SELECT * FROM pocs WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'PoC not found' });
    }
    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
