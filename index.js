const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const cors = require('cors');  // Importing cors

// Secret key (make sure to store it in .env)
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

const app = express();
const port = process.env.PORT || 5001;

// Enable CORS for the React frontend running on localhost:3000
app.use(cors({
  origin: 'http://localhost:3000', // Replace this with your frontend's URL
  credentials: true,
}));

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

    // Generate JWT token, including the user's access level and role
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        access: user.access,   // Include access level in the JWT payload
        role: user.role        // Include role in the JWT payload
      },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Send token to client
    res.status(200).json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get milestones for a specific deal
app.get('/deals/:id/milestones', authenticateToken, async (req, res) => {
  const dealId = req.params.id;

  try {
    // Fetch all milestones where deal_id matches the given dealId
    const result = await pool.query('SELECT * FROM deal_milestone WHERE deal_id = $1', [dealId]);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Creating a note for a deal
app.post('/deals/:id/notes', authenticateToken, async (req, res) => {
  const { id } = req.params; // deal ID
  const { content, title, isShared } = req.body; // include title in request body

  try {
    const result = await pool.query(
      `INSERT INTO deal_notes (deal_id, content, title, is_shared, created_at, updated_at)
          VALUES ($1, $2, $3, $4, NOW(), NOW()) RETURNING *`,
      [id, content, title || 'Untitled Note', isShared]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating note:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



app.get('/deals/:id/notes', authenticateToken, async (req, res) => {
  const dealId = req.params.id;

  try {
    const result = await pool.query('SELECT * FROM deal_notes WHERE deal_id = $1', [dealId]);
    res.status(200).json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/notes/:id/share', authenticateToken, async (req, res) => {
  const noteId = req.params.id;
  const { sharedWithUserId } = req.body;

  try {
    await pool.query(
      'INSERT INTO shared_notes (note_id, shared_with_user_id) VALUES ($1, $2)',
      [noteId, sharedWithUserId]
    );
    res.status(200).json({ message: 'Note shared successfully' });
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
    req.user = verified; // Attach user info (id, access, role) from the token to the request
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
  body('role').optional().isIn(['user', 'admin']).withMessage('Role must be either user or admin'),
  body('access').optional().isIn(['sales_engineer', 'manager', 'customer']).withMessage('Access level must be sales_engineer, manager, or customer')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password, first_name, last_name, role, access } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, first_name, last_name, role, access) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [email, hashedPassword, first_name, last_name, role, access]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route: Get all deals (only deals the user is allowed to see)
app.get('/deals', authenticateToken, async (req, res) => {
  try {
    let result;
    console.log(req.user.access);
    console.log(req.user.id);
    // Sellers: See only deals they created
    if (req.user.access === 'seller') {
      result = await pool.query('SELECT * FROM deals WHERE created_by = $1', [req.user.id]);

      // Sales Engineers: See deals they created or shared with them
    } else if (req.user.access === 'sales_engineer') {
      result = await pool.query(
        `SELECT * FROM deals 
         WHERE created_by = $1 OR id IN (SELECT deal_id FROM deal_shared_users WHERE user_id = $1)`,
        [req.user.id]
      );

      // Managers: See deals from their team
    } else if (req.user.access === 'manager') {
      result = await pool.query(
        `SELECT d.* FROM deals d 
         JOIN users u ON d.created_by = u.id 
         JOIN team_members tm ON u.id = tm.user_id 
         JOIN teams t ON tm.team_id = t.team_id 
         WHERE t.manager_id = $1`,
        [req.user.id]
      );

      // Customers: See only deals shared with them
    } else if (req.user.access === 'customer') {
      result = await pool.query(
        `SELECT * FROM deals 
         WHERE id IN (SELECT deal_id FROM deal_shared_users WHERE user_id = $1)`,
        [req.user.id]
      );

    } else {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.status(200).json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/deals/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('SELECT * FROM deals WHERE id = $1', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Deal not found' });
    }

    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});



// Protected route: Get all PoCs
app.get('/pocs', async (req, res) => {
  console.log(req.user);
  try {
    // Example of access-level filtering
    if (req.user.access === 'manager') {
      const result = await pool.query('SELECT * FROM pocs WHERE created_by = $1', [req.user.id]);
      res.status(200).json(result.rows);
    } else if (req.user.access === 'sales_engineer') {
      const result = await pool.query('SELECT * FROM pocs WHERE created_by = $1', [req.user.id]);
      res.status(200).json(result.rows);
    } else if (req.user.access === 'customer') {
      const result = await pool.query('SELECT * FROM pocs WHERE customer_id = $1', [req.user.id]);
      res.status(200).json(result.rows);
    } else {
      res.status(403).json({ error: 'Access denied' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route: Create a new PoC
// Create a new PoC
app.post('/pocs', [
  body('poc_name').notEmpty().withMessage('PoC name is required'),
  body('customer_name').notEmpty().withMessage('Customer name is required'),
  body('start_date').optional().isISO8601().withMessage('Start date must be a valid date'),
  body('end_date').optional().isISO8601().withMessage('End date must be a valid date'),
  body('status').isIn(['ongoing', 'completed']).withMessage('Status must be ongoing or completed'),
  body('dollar_value').optional().isFloat({ min: 0 }).withMessage('Dollar value must be a valid number')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { poc_name, customer_name, start_date, end_date, status, dollar_value } = req.body;

  try {
    const result = await pool.query(
      'INSERT INTO pocs (poc_name, customer_name, start_date, end_date, status, dollar_value, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [poc_name, customer_name, start_date, end_date, status, dollar_value, req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get contacts for a specific PoC
app.get('/pocs/:id/contacts', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('SELECT * FROM customer_contacts WHERE poc_id = $1', [id]);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Failed to fetch contacts:', error);
    res.status(500).json({ error: 'Failed to fetch contacts' });
  }
});

// Add a new required capability to a PoC
// Add a new required capability to a PoC
app.post('/pocs/:id/capabilities', authenticateToken, [
  body('capability_description').notEmpty().withMessage('Capability description is required'),
], async (req, res) => {
  const { id } = req.params;
  const { capability_description } = req.body;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const result = await pool.query(
      'INSERT INTO required_capabilities (poc_id, capability_description) VALUES ($1, $2) RETURNING *',
      [id, capability_description]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Failed to add capability:', error);
    res.status(500).json({ error: 'Failed to add capability' });
  }
});

// Get all required capabilities for a specific PoC
app.get('/pocs/:id/capabilities', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('SELECT * FROM required_capabilities WHERE poc_id = $1', [id]);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Failed to fetch capabilities:', error);
    res.status(500).json({ error: 'Failed to fetch capabilities' });
  }
});

// Add a new use case to a PoC
app.post('/pocs/:id/use_cases', authenticateToken, [
  body('use_case_description').notEmpty().withMessage('Use case description is required'),
], async (req, res) => {
  const { id } = req.params;
  const { use_case_description } = req.body;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const result = await pool.query(
      'INSERT INTO use_cases (poc_id, use_case_description) VALUES ($1, $2) RETURNING *',
      [id, use_case_description]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Failed to add use case:', error);
    res.status(500).json({ error: 'Failed to add use case' });
  }
});

// Get all use cases for a specific PoC
app.get('/pocs/:id/use_cases', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('SELECT * FROM use_cases WHERE poc_id = $1', [id]);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Failed to fetch use cases:', error);
    res.status(500).json({ error: 'Failed to fetch use cases' });
  }
});

// Add a new success criterion to a PoC
app.post('/pocs/:id/success_criteria', authenticateToken, [
  body('criteria_description').notEmpty().withMessage('Criteria description is required'),
], async (req, res) => {
  const { id } = req.params;
  const { criteria_description } = req.body;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const result = await pool.query(
      'INSERT INTO success_criteria (poc_id, criteria_description, is_met) VALUES ($1, $2, $3) RETURNING *',
      [id, criteria_description, false]  // `is_met` starts as false by default
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Failed to add success criterion:', error);
    res.status(500).json({ error: 'Failed to add success criterion' });
  }
});

// Get all success criteria for a specific PoC
app.get('/pocs/:id/success_criteria', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('SELECT * FROM success_criteria WHERE poc_id = $1', [id]);
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Failed to fetch success criteria:', error);
    res.status(500).json({ error: 'Failed to fetch success criteria' });
  }
});






// Add a new contact to a PoC
app.post('/pocs/:id/contacts', authenticateToken, [
  body('contact_name').notEmpty().withMessage('Contact name is required'),
  body('contact_email').isEmail().withMessage('A valid email is required'),
  body('role').notEmpty().withMessage('Role is required'),
  body('status').isIn(['champion', 'detractor', 'neutral', 'coach']).withMessage('Invalid status value')
], async (req, res) => {
  const { id } = req.params;
  const { contact_name, contact_email, role, status } = req.body;

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const result = await pool.query(
      'INSERT INTO customer_contacts (poc_id, contact_name, contact_email, role, status) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [id, contact_name, contact_email, role, status]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Failed to add contact:', error);
    res.status(500).json({ error: 'Failed to add contact' });
  }
});




// Protected route: Get a specific PoC by ID
app.get('/pocs/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('SELECT * FROM pocs WHERE id = $1 AND (created_by = $2 OR customer_id = $2)', [id, req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'PoC not found or access denied' });
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
