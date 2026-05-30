// db.js
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  
  // ADD THESE SETTINGS TO PREVENT HANGING:
  connectionTimeoutMillis: 5000, // timeout after 5 seconds if connecting fails
  idleTimeoutMillis: 30000,      // drop connections after 30 seconds of inactivity
  max: 10                        // limit concurrent connections 
});

// Optional: Add an error listener to prevent the app from crashing on idle DB errors
pool.on('error', (err, client) => {
  console.error('Unexpected error on idle client', err);
});

module.exports = pool;