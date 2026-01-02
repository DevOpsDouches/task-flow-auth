// auth-service/src/controllers/authController.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool } = require('../config/database');
const { RANK_THRESHOLDS } = require('../utils/ranks');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Create Account Endpoint
async function register(req, res) {
  let connection;
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }

    connection = await pool.getConnection();

    // Check if user already exists
    const [existingUsers] = await connection.query(
      'SELECT user_id FROM users WHERE username = ?',
      [username]
    );

    if (existingUsers.length > 0) {
      connection.release();
      return res.status(409).json({
        success: false,
        message: 'Username already exists'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user with default rank (iron)
    const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    await connection.query(
      'INSERT INTO users (user_id, username, password, current_rank, total_completed_tasks) VALUES (?, ?, ?, ?, ?)',
      [userId, username, hashedPassword, 'iron', 0]
    );

    connection.release();

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      userId
    });

  } catch (error) {
    if (connection) connection.release();
    console.error('Register error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
}

// Login Endpoint
async function login(req, res) {
  let connection;
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }

    connection = await pool.getConnection();

    // Get user from database with rank info
    const [users] = await connection.query(
      'SELECT user_id, username, password, current_rank, total_completed_tasks FROM users WHERE username = ?',
      [username]
    );

    connection.release();

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    const user = users[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.user_id, 
        username: user.username 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Get rank display info
    const rankInfo = RANK_THRESHOLDS[user.current_rank] || RANK_THRESHOLDS.iron;

    res.json({
      success: true,
      token,
      userId: user.user_id,
      username: user.username,
      rank: {
        current: user.current_rank,
        displayName: rankInfo.displayName,
        color: rankInfo.color,
        totalCompleted: user.total_completed_tasks
      }
    });

  } catch (error) {
    if (connection) connection.release();
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
}

// Verify Token Endpoint
async function verifyToken(req, res) {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    res.json({
      success: true,
      userId: decoded.userId,
      username: decoded.username
    });

  } catch (error) {
    res.status(401).json({
      success: false,
      message: 'Invalid token'
    });
  }
}

// Logout Endpoint
async function logout(req, res) {
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
}

// Get User Profile with Rank Info
async function getProfile(req, res) {
  let connection;
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    connection = await pool.getConnection();

    const [users] = await connection.query(
      'SELECT user_id, username, current_rank, total_completed_tasks, created_at, rank_upgraded_at FROM users WHERE user_id = ?',
      [decoded.userId]
    );

    connection.release();

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const user = users[0];
    const rankInfo = RANK_THRESHOLDS[user.current_rank] || RANK_THRESHOLDS.iron;

    res.json({
      success: true,
      user: {
        userId: user.user_id,
        username: user.username,
        createdAt: user.created_at,
        rank: {
          current: user.current_rank,
          displayName: rankInfo.displayName,
          color: rankInfo.color,
          totalCompleted: user.total_completed_tasks,
          upgradedAt: user.rank_upgraded_at
        }
      }
    });

  } catch (error) {
    if (connection) connection.release();
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
}

module.exports = {
  register,
  login,
  verifyToken,
  logout,
  getProfile
};
