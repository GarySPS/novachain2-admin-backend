const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();
console.log("LOADED ADMIN_PASSWORD:", process.env.ADMIN_PASSWORD);
const bcrypt = require('bcrypt');
const pool = require('./db');
const path = require('path');

const app = express();
const PORT = 5001;

// We have removed multer, fs, and FormData - they are not needed.

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@novachain.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'SuperSecret123';
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const BCRYPT_ROUNDS = 10;

const MAIN_BACKEND_URL = 'https://novachain2-backend.onrender.com';

const userAutoWin = {};
let AUTO_WINNING = true;

const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:3001',
  'https://novachain2-admin-frontend.vercel.app'
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow REST tools without origin (Postman)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('CORS Not Allowed: ' + origin));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json()); // Use JSON body parser

// ===== NEW: Seed Admin Users from .env into DB =====
const seedAdmins = async () => {
  console.log('Checking admin accounts...');
  const adminsToSeed = [
    {
      email: process.env.ADMIN_EMAIL,
      password: process.env.ADMIN_PASSWORD,
      role: 'superadmin'
    },
    {
      email: process.env.SUPPORT_EMAIL,
      password: process.env.SUPPORT_PASSWORD,
      role: 'support'
    }
  ];

  for (const admin of adminsToSeed) {
    if (!admin.email || !admin.password) continue;

    try {
      // Check if admin already exists
      const { rows } = await pool.query('SELECT * FROM admin_users WHERE email = $1', [admin.email]);
      
      if (rows.length === 0) {
        // Admin doesn't exist, create them
        const password_hash = await bcrypt.hash(admin.password, BCRYPT_ROUNDS);
        await pool.query(
          'INSERT INTO admin_users (email, password_hash, role) VALUES ($1, $2, $3)',
          [admin.email, password_hash, admin.role]
        );
        console.log(`Created admin user: ${admin.email}`);
      }
    } catch (err) {
      console.error(`Failed to seed admin ${admin.email}:`, err.message);
    }
  }
};
// Run seeder on startup
seedAdmins();

// ===== JWT admin auth middleware =====
function requireAdminAuth(req, res, next) {
  const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.adminRole = decoded.role;
    req.adminEmail = decoded.email;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

// ===== NEW: Superadmin only middleware =====
function requireSuperAdmin(req, res, next) {
  if (req.adminRole !== 'superadmin') {
    return res.status(403).json({ message: 'Only superadmin can access this.' });
  }
  next();
}

// ====== PROXY ROUTES (no change) ======
app.get('/api/trades', requireAdminAuth, async (req, res) => {
  try {
    const r = await axios.get(`${MAIN_BACKEND_URL}/api/trades`, {
      headers: { 'x-admin-token': process.env.ADMIN_API_TOKEN }
    });
    res.json(r.data);
  } catch (err) {
    console.error("TRADES PROXY ERROR:", err.response?.data || err.message, err.response?.status || "");
    res.status(500).json({ message: 'Failed to fetch trades', detail: err.message });
  }
});

app.get('/api/deposits', requireAdminAuth, async (req, res) => {
  try {
    const r = await axios.get(`${MAIN_BACKEND_URL}/api/deposits`, {
      headers: { 'x-admin-token': process.env.ADMIN_API_TOKEN }
    });
    res.json(r.data);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch deposits', detail: err.message });
  }
});

app.get('/api/withdrawals', requireAdminAuth, async (req, res) => {
  try {
    const r = await axios.get(`${MAIN_BACKEND_URL}/api/withdrawals`, {
      headers: { 'x-admin-token': process.env.ADMIN_API_TOKEN }
    });
    res.json(r.data);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch withdrawals', detail: err.message });
  }
});

// ===== NORMAL ADMIN CONTROLS (NOT PROXIED) =====

// --- Admin login
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    const { rows } = await pool.query('SELECT * FROM admin_users WHERE email = $1', [email]);
    const admin = rows[0];

    // Check if admin exists and password is correct
    if (!admin || !(await bcrypt.compare(password, admin.password_hash))) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Password is correct, issue token
    const token = jwt.sign({ email: admin.email, role: admin.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, role: admin.role }); // send role to frontend too!

  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// --- Admin Change Password
app.post('/api/admin/change-password', requireAdminAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const adminEmail = req.adminEmail; // From requireAdminAuth middleware

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ message: 'Old and new passwords are required' });
  }
  
  if (newPassword.length < 6) {
     return res.status(400).json({ message: 'New password must be at least 6 characters' });
  }

  try {
    // 1. Get current user from DB
    const { rows } = await pool.query('SELECT * FROM admin_users WHERE email = $1', [adminEmail]);
    const admin = rows[0];

    if (!admin) {
      return res.status(404).json({ message: 'Admin user not found' });
    }

    // 2. Check if old password is correct
    const isMatch = await bcrypt.compare(oldPassword, admin.password_hash);
    if (!isMatch) {
      return res.status(401).json({ message: 'Incorrect old password' });
    }

    // 3. Hash and update new password
    const new_password_hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    await pool.query(
      'UPDATE admin_users SET password_hash = $1 WHERE email = $2',
      [new_password_hash, adminEmail]
    );

    res.json({ message: 'Password changed successfully' });

  } catch (err) {
    console.error('Change password error:', err.message);
    res.status(500).json({ message: 'Server error changing password' });
  }
});

// --- RESTRICTED: Wallet Settings (Deposit Address) Routes [PROXY] ---
app.post(
  '/api/admin/deposit-addresses',
  requireAdminAuth,
  requireSuperAdmin, // <-- superadmin only!
// We removed upload.any() because we are now sending JSON
  async (req, res) => {
    try {
      // req.body is now simple JSON (an array) sent from the frontend
      const payload = req.body;

      // Proxy the JSON request to the main backend
      const axiosRes = await axios.post(
        `${MAIN_BACKEND_URL}/api/admin/deposit-addresses`, 
        payload, // Send the JSON payload directly
        {
          headers: {
            'Content-Type': 'application/json', // Tell the main backend it's JSON
            'x-admin-token': process.env.ADMIN_API_TOKEN 
          }
        }
      );
      
      // Send response from main backend back to admin frontend
      res.status(axiosRes.status).json(axiosRes.data);

    } catch (err) {
      console.error("DEPOSIT PROXY ERROR (JSON):", err.response?.data || err.message);
      res.status(err.response?.status || 500).json({ 
        message: "Failed to proxy deposit settings", 
        detail: err.response?.data?.message || err.message 
  	  });
    }
  }
);

app.get(
  '/api/admin/deposit-addresses',
  requireAdminAuth,
  requireSuperAdmin, // <-- superadmin only!
  async (req, res) => {
    try {
      // Proxy the GET request to the main backend
      const axiosRes = await axios.get(
        `${MAIN_BACKEND_URL}/api/admin/deposit-addresses`, // <-- PROXY
        {
          headers: { 'x-admin-token': process.env.ADMIN_API_TOKEN } // <-- Auth
        }
      );
      res.json(axiosRes.data); // Send data back to admin frontend
    } catch (err) {
      console.error("GET DEPOSIT PROXY ERROR:", err.response?.data || err.message);
      res.status(err.response?.status || 500).json({ 
        message: "Failed to fetch deposit addresses",
        detail: err.response?.data?.message || err.message
      });
    }
  }
);

// Fetch users (full info for admin table)
app.get('/api/admin/users', requireAdminAuth, async (req, res) => {
  try {
    // Get users (NO frozen column in users!)
    const usersResult = await pool.query(
      `SELECT id, email, username, password, created_at, kyc_status, kyc_id_card, kyc_selfie FROM users ORDER BY id DESC`
    );

    const users = usersResult.rows;

    // Get all balances (frozen is in user_balances!)
    const balancesResult = await pool.query(
      `SELECT user_id, coin, balance, frozen FROM user_balances`
    );
    const balances = balancesResult.rows;

    // Merge balances into users (USDT only)
    const usersWithBalances = users.map(u => {
      const userBalances = balances.filter(b => b.user_id === u.id);
      const usdt = userBalances.find(b => b.coin === "USDT") || {};
      return {
        ...u,
        balance: Number(usdt.balance || 0),
        frozen_balance: Number(usdt.frozen || 0), // from user_balances
      }
    });

    res.json(usersWithBalances);
  } catch (err) {
    console.error("USERS ERROR:", err);
    res.status(500).json({ message: 'Failed to fetch users with balances', detail: err.message });
  }
});

app.delete('/api/admin/user/:id', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM wallets WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM user_balances WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM trades WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM deposits WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM withdrawals WHERE user_id = $1`, [id]);
    await client.query(`DELETE FROM users WHERE id = $1`, [id]);
    await client.query('COMMIT');
    res.json({ message: `User #${id} and all related data deleted.` });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ message: 'Failed to delete user', detail: err.message });
  } finally {
    client.release();
  }
});
app.post('/api/admin/user-kyc-status', requireAdminAuth, async (req, res) => {
  const { user_id, kyc_status } = req.body;
  if (!user_id || !['approved', 'rejected', 'pending'].includes(kyc_status)) {
    return res.status(400).json({ message: "Invalid input" });
  }
  try {
    await pool.query(
      `UPDATE users SET kyc_status = $1 WHERE id = $2`,
      [kyc_status, user_id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ message: "DB error" });
  }
});
 app.get('/api/admin/user/:id/kyc', requireAdminAuth, async (req, res) => {
   const { id } = req.params;
   try {
     const { rows } = await pool.query(
       `SELECT kyc_selfie, kyc_id_card, kyc_status FROM users WHERE id = $1`,
       [id]
     );
     if (!rows[0]) return res.status(404).json({ error: "User not found" });
     // Return the stored (Supabase) public URLs as-is
     res.json(rows[0]);
   } catch (err) {
     res.status(500).json({ error: "DB error" });
   }
 });

app.post('/api/admin/auto-winning', requireAdminAuth, (req, res) => {
  const { enabled } = req.body;
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ message: 'Invalid value for enabled' });
  }
  AUTO_WINNING = enabled;
  res.json({ message: `AUTO_WINNING set to ${AUTO_WINNING}` });
});
// NEW - proxy to main backend!
app.get('/api/admin/user-win-modes', requireAdminAuth, async (req, res) => {
  try {
    const r = await axios.get(`${MAIN_BACKEND_URL}/api/admin/user-win-modes`, {
      headers: { 'x-admin-token': process.env.ADMIN_API_TOKEN }
    });
    res.json(r.data);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch user win modes', detail: err.message });
  }
});


// Trade result, user status, etc.
app.post('/api/admin/user-status', requireAdminAuth, async (req, res) => {
  const { userId, newStatus } = req.body;
  if (!userId || !['active', 'suspended'].includes(newStatus)) {
    return res.status(400).json({ message: 'Invalid input' });
  }
  try {
    await pool.query(
      'UPDATE users SET status = $1 WHERE id = $2',
      [newStatus, userId]
    );
    res.json({ message: `User ${userId} status changed to ${newStatus}` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update status', detail: err.message });
  }
});
app.post('/api/admin/update-trade', requireAdminAuth, async (req, res) => {
  const { tradeId, result } = req.body;
  if (!tradeId || !['Win', 'Loss'].includes(result)) {
    return res.status(400).json({ message: 'Invalid input' });
  }
  try {
    await pool.query(
      'UPDATE trades SET result = $1 WHERE id = $2',
      [result, tradeId]
    );
    res.json({ message: `Trade ${tradeId} updated to ${result}` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update trade', detail: err.message });
  }
});

// Approve/deny deposit/withdrawal (PROXIED to main backend - CORRECTED)
app.post('/api/admin/deposits/:id/approve', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    console.log(`Approving deposit ${id} via proxy to main backend`);
    
    // Use the CORRECT endpoint that exists in your main backend
    const axiosRes = await axios.put(
      `${MAIN_BACKEND_URL}/api/deposits/${id}/status`,
      { status: "approved" },
      {
        headers: { 
          'x-admin-token': process.env.ADMIN_API_TOKEN,
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log(`Deposit ${id} approved successfully`);
    res.status(axiosRes.status).json(axiosRes.data);
    
  } catch (err) {
    console.error("DEPOSIT APPROVE PROXY ERROR:", {
      message: err.message,
      response: err.response?.data,
      status: err.response?.status,
      url: `${MAIN_BACKEND_URL}/api/deposits/${id}/status`
    });
    
    res.status(err.response?.status || 500).json({
      message: 'Failed to approve deposit',
      detail: err.response?.data?.message || err.message
    });
  }
});

app.post('/api/admin/deposits/:id/deny', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    console.log(`Denying deposit ${id} via proxy to main backend`);
    
    const axiosRes = await axios.put(
      `${MAIN_BACKEND_URL}/api/deposits/${id}/status`,
      { status: "rejected" },
      {
        headers: { 
          'x-admin-token': process.env.ADMIN_API_TOKEN,
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log(`Deposit ${id} denied successfully`);
    res.status(axiosRes.status).json(axiosRes.data);
    
  } catch (err) {
    console.error("DEPOSIT DENY PROXY ERROR:", {
      message: err.message,
      response: err.response?.data,
      status: err.response?.status
    });
    
    res.status(err.response?.status || 500).json({
      message: 'Failed to deny deposit',
      detail: err.response?.data?.message || err.message
    });
  }
});

// === WITHDRAWAL APPROVAL ROUTES (ADD THESE) ===
app.post('/api/admin/withdrawals/:id/approve', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    console.log(`Approving withdrawal ${id} via proxy to main backend`);
    
    const axiosRes = await axios.post(
      `${MAIN_BACKEND_URL}/api/withdrawals/${id}/status`,
      { status: "approved" },
      {
        headers: { 
          'x-admin-token': process.env.ADMIN_API_TOKEN,
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log(`Withdrawal ${id} approved successfully`);
    res.status(axiosRes.status).json(axiosRes.data);
    
  } catch (err) {
    console.error("WITHDRAWAL APPROVE PROXY ERROR:", {
      message: err.message,
      response: err.response?.data,
      status: err.response?.status,
      url: `${MAIN_BACKEND_URL}/api/withdrawals/${id}/status`
    });
    
    res.status(err.response?.status || 500).json({
      message: 'Failed to approve withdrawal',
      detail: err.response?.data?.message || err.message
    });
  }
});

app.post('/api/admin/withdrawals/:id/deny', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    console.log(`Denying withdrawal ${id} via proxy to main backend`);
    
    const axiosRes = await axios.put(
      `${MAIN_BACKEND_URL}/api/withdrawals/${id}/status`,
      { status: "rejected" },
      {
        headers: { 
          'x-admin-token': process.env.ADMIN_API_TOKEN,
          'Content-Type': 'application/json'
        }
      }
    );
    
    console.log(`Withdrawal ${id} denied successfully`);
    res.status(axiosRes.status).json(axiosRes.data);
    
  } catch (err) {
    console.error("WITHDRAWAL DENY PROXY ERROR:", {
      message: err.message,
      response: err.response?.data,
      status: err.response?.status
    });
    
    res.status(err.response?.status || 500).json({
      message: 'Failed to deny withdrawal',
      detail: err.response?.data?.message || err.message
    });
  }
});

// Add this debug route to test the connection
app.get('/api/admin/debug-connection', requireAdminAuth, async (req, res) => {
  try {
    const testRes = await axios.get(`${MAIN_BACKEND_URL}/api/deposits`, {
      headers: { 'x-admin-token': process.env.ADMIN_API_TOKEN }
    });
    res.json({ 
      status: 'SUCCESS', 
      mainBackendStatus: 'reachable',
      responseLength: testRes.data.length 
    });
  } catch (err) {
    res.json({ 
      status: 'ERROR', 
      mainBackendStatus: 'unreachable',
      error: err.message,
      adminTokenExists: !!process.env.ADMIN_API_TOKEN
    });
  }
});

// TEMP DEBUG ROUTES (optional)
app.get('/debug/deposits', requireAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns
      WHERE table_name = 'deposits'
    `);
    res.json(result.rows);
  } catch (err) {
    res.json({ error: err.message });
  }
});
app.get('/debug/trades', requireAdminAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns
      WHERE table_name = 'trades'
    `);
    res.json(result.rows);
  } catch (err) {
    res.json({ error: err.message });
  }
});

// Trade-mode control (proxy to main backend)
app.post('/api/admin/users/:user_id/trade-mode', requireAdminAuth, async (req, res) => {
  const { user_id } = req.params;
  const { mode } = req.body;
  if (!user_id || !['WIN', 'LOSE', null, ""].includes(mode)) {
    return res.status(400).json({ message: 'Invalid input' });
  }
  try {
    const axiosRes = await axios.post(
  `${MAIN_BACKEND_URL}/api/admin/users/${user_id}/trade-mode`,
      { mode: mode || null },
  {
    headers: { 'x-admin-token': process.env.ADMIN_API_TOKEN }
  }
);

    res.json({ success: true, ...axiosRes.data });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update user mode', detail: err.message });
  }
});

// === Manual Balance Add ===
app.post('/api/admin/add-balance', requireAdminAuth, async (req, res) => {
  const { user_id, coin, amount } = req.body;
  if (!user_id || !coin || !amount || isNaN(amount)) {
    return res.status(400).json({ message: 'Missing or invalid parameters' });
  }
  try {
    await pool.query(
      `INSERT INTO user_balances (user_id, coin, balance)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, coin)
       DO UPDATE SET balance = user_balances.balance + EXCLUDED.balance`,
      [user_id, coin, amount]
    );
    res.json({ message: `Added ${amount} ${coin} to user ${user_id}` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to add balance', detail: err.message });
  }
});

// === Manual Balance Reduce ===
app.post('/api/admin/user/:id/reduce-balance', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  const { coin, amount } = req.body;
  if (!id || !coin || !amount || isNaN(amount)) {
    return res.status(400).json({ message: 'Missing or invalid parameters' });
  }
  try {
    const { rowCount } = await pool.query(
      `UPDATE user_balances
        SET balance = balance - $1
        WHERE user_id = $2 AND coin = $3 AND balance >= $1`,
      [amount, id, coin]
    );
    if (rowCount === 0) {
      return res.status(400).json({ message: "Insufficient balance or invalid user/coin" });
    }
    res.json({ message: `Reduced ${amount} ${coin} from user ${id}` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to reduce balance', detail: err.message });
  }
});

// === Freeze Balance ===
app.post('/api/admin/freeze-balance', requireAdminAuth, async (req, res) => {
  const { user_id, coin, amount } = req.body;
  if (!user_id || !coin || !amount || isNaN(amount)) {
    return res.status(400).json({ message: 'Missing or invalid parameters' });
  }
  try {
    const { rowCount } = await pool.query(
      `UPDATE user_balances
       SET balance = balance - $1,
           frozen = COALESCE(frozen, 0) + $1
       WHERE user_id = $2 AND coin = $3 AND balance >= $1`,
      [amount, user_id, coin]
    );

    if (rowCount === 0) {
      return res.status(400).json({ message: "Insufficient balance or invalid user/coin" });
    }

    res.json({ message: `Froze ${amount} ${coin} for user ${user_id}` });
  } catch (err) {
    res.status(500).json({ message: 'Failed to freeze balance', detail: err.message });
  }
});

// === GET User Balances for Admin Table ===
app.get('/api/admin/user/:id/balances', requireAdminAuth, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query(
      `SELECT coin, balance, frozen FROM user_balances WHERE user_id = $1 ORDER BY coin ASC`,
      [id]
    );
    res.json({ balances: rows });
  } catch (err) {
//
    res.status(500).json({ message: "Failed to fetch user balances", detail: err.message });
  }
});

// --- NEW: KYC approve/reject (endpoint used by AdminKYC UI)
app.post('/kyc/admin/status', requireAdminAuth, async (req, res) => {
  const { user_id, status } = req.body;
  if (!user_id || !['approved', 'rejected', 'pending'].includes(status)) {
    return res.status(400).json({ error: "Invalid input" });
  }
  try {
    await pool.query(
      `UPDATE users SET kyc_status = $1 WHERE id = $2`,
      [status, user_id]
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "DB error" });
  }
});


app.listen(PORT, () => {
  console.log(`NovaChain Admin Backend running on port ${PORT}`);
});
