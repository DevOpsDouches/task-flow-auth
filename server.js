// Auth Service with Social Features
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const RANK_THRESHOLDS = {
  iron: { min: 0, max: 9, displayName: 'Iron', color: '#9CA3AF' },
  silver: { min: 10, max: 24, displayName: 'Silver', color: '#C0C0C0' },
  gold: { min: 25, max: 49, displayName: 'Gold', color: '#FFD700' },
  diamond: { min: 50, max: 99, displayName: 'Diamond', color: '#B9F2FF' },
  platinum: { min: 100, max: 199, displayName: 'Platinum', color: '#E5E4E2' },
  todo_master: { min: 200, max: Infinity, displayName: 'Todo Master', color: '#DC2626' }
};

const verifyToken = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'No token provided' });
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();
    
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        user_id VARCHAR(255) PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        display_name VARCHAR(255) DEFAULT NULL,
        bio TEXT DEFAULT NULL,
        avatar_url VARCHAR(512) DEFAULT NULL,
        current_rank VARCHAR(50) DEFAULT 'iron',
        total_completed_tasks INT DEFAULT 0,
        rank_upgraded_at TIMESTAMP NULL,
        is_public BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_username (username)
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS friendships (
        friendship_id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        friend_id VARCHAR(255) NOT NULL,
        status ENUM('pending', 'accepted', 'blocked') DEFAULT 'pending',
        requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        accepted_at TIMESTAMP NULL,
        INDEX idx_user_id (user_id),
        INDEX idx_friend_id (friend_id),
        UNIQUE KEY unique_friendship (user_id, friend_id),
        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
        FOREIGN KEY (friend_id) REFERENCES users(user_id) ON DELETE CASCADE
      )
    `);
    
    connection.release();
    console.log('✓ Database tables initialized');
  } catch (error) {
    console.error('✗ Error initializing database:', error.message);
  }
}

initializeDatabase();

app.get('/health', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.query('SELECT 1');
    connection.release();
    res.json({ status: 'OK', service: 'auth-service', database: 'connected' });
  } catch (error) {
    res.status(503).json({ status: 'ERROR', service: 'auth-service', database: 'disconnected' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  let connection;
  try {
    const { username, password, displayName } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    }

    connection = await pool.getConnection();
    const [existing] = await connection.query('SELECT user_id FROM users WHERE username = ?', [username]);
    if (existing.length > 0) {
      connection.release();
      return res.status(409).json({ success: false, message: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    await connection.query(
      'INSERT INTO users (user_id, username, password, display_name, current_rank, total_completed_tasks) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, username, hashedPassword, displayName || username, 'iron', 0]
    );

    connection.release();
    res.status(201).json({ success: true, message: 'Account created successfully', userId });
  } catch (error) {
    if (connection) connection.release();
    console.error('Register error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  let connection;
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required' });
    }

    connection = await pool.getConnection();
    const [users] = await connection.query(
      'SELECT user_id, username, password, display_name, current_rank, total_completed_tasks, avatar_url FROM users WHERE username = ?',
      [username]
    );

    if (users.length === 0) {
      connection.release();
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const user = users[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      connection.release();
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    await connection.query('UPDATE users SET last_active = NOW() WHERE user_id = ?', [user.user_id]);
    connection.release();

    const token = jwt.sign({ userId: user.user_id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    const rankInfo = RANK_THRESHOLDS[user.current_rank] || RANK_THRESHOLDS.iron;

    res.json({
      success: true,
      token,
      userId: user.user_id,
      username: user.username,
      displayName: user.display_name,
      avatarUrl: user.avatar_url,
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
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.post('/api/auth/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'No token provided' });
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ success: true, userId: decoded.userId, username: decoded.username });
  } catch (error) {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
});

app.get('/api/auth/profile', verifyToken, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [users] = await connection.query(
      'SELECT user_id, username, display_name, bio, avatar_url, current_rank, total_completed_tasks, is_public, created_at FROM users WHERE user_id = ?',
      [req.user.userId]
    );
    connection.release();

    if (users.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const user = users[0];
    const rankInfo = RANK_THRESHOLDS[user.current_rank] || RANK_THRESHOLDS.iron;

    res.json({
      success: true,
      user: {
        userId: user.user_id,
        username: user.username,
        displayName: user.display_name,
        bio: user.bio,
        avatarUrl: user.avatar_url,
        isPublic: user.is_public,
        createdAt: user.created_at,
        rank: {
          current: user.current_rank,
          displayName: rankInfo.displayName,
          color: rankInfo.color,
          totalCompleted: user.total_completed_tasks
        }
      }
    });
  } catch (error) {
    if (connection) connection.release();
    console.error('Get profile error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.put('/api/auth/profile', verifyToken, async (req, res) => {
  let connection;
  try {
    const { displayName, bio, avatarUrl, isPublic } = req.body;
    connection = await pool.getConnection();

    let updates = [];
    let values = [];

    if (displayName !== undefined) { updates.push('display_name = ?'); values.push(displayName); }
    if (bio !== undefined) { updates.push('bio = ?'); values.push(bio); }
    if (avatarUrl !== undefined) { updates.push('avatar_url = ?'); values.push(avatarUrl); }
    if (isPublic !== undefined) { updates.push('is_public = ?'); values.push(isPublic); }

    if (updates.length === 0) {
      connection.release();
      return res.status(400).json({ success: false, message: 'No fields to update' });
    }

    values.push(req.user.userId);
    await connection.query(`UPDATE users SET ${updates.join(', ')}, updated_at = NOW() WHERE user_id = ?`, values);
    const [users] = await connection.query(
      'SELECT user_id, username, display_name, bio, avatar_url, is_public FROM users WHERE user_id = ?',
      [req.user.userId]
    );
    connection.release();

    res.json({ success: true, user: users[0] });
  } catch (error) {
    if (connection) connection.release();
    console.error('Update profile error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.get('/api/community/search', verifyToken, async (req, res) => {
  let connection;
  try {
    const { query, limit = 20 } = req.query;
    connection = await pool.getConnection();

    let sql, params;
    if (query) {
      sql = `SELECT user_id, username, display_name, avatar_url, current_rank, total_completed_tasks, last_active
             FROM users WHERE is_public = TRUE AND user_id != ? AND (username LIKE ? OR display_name LIKE ?)
             ORDER BY total_completed_tasks DESC LIMIT ?`;
      params = [req.user.userId, `%${query}%`, `%${query}%`, parseInt(limit)];
    } else {
      sql = `SELECT user_id, username, display_name, avatar_url, current_rank, total_completed_tasks, last_active
             FROM users WHERE is_public = TRUE AND user_id != ?
             ORDER BY total_completed_tasks DESC LIMIT ?`;
      params = [req.user.userId, parseInt(limit)];
    }

    const [users] = await connection.query(sql, params);
    const userIds = users.map(u => u.user_id);
    let friendships = [];
    
    if (userIds.length > 0) {
      const [friendshipData] = await connection.query(
        'SELECT friend_id, status FROM friendships WHERE user_id = ? AND friend_id IN (?)',
        [req.user.userId, userIds]
      );
      friendships = friendshipData;
    }

    connection.release();

    const result = users.map(user => {
      const friendship = friendships.find(f => f.friend_id === user.user_id);
      const rankInfo = RANK_THRESHOLDS[user.current_rank] || RANK_THRESHOLDS.iron;
      
      return {
        userId: user.user_id,
        username: user.username,
        displayName: user.display_name,
        avatarUrl: user.avatar_url,
        rank: {
          current: user.current_rank,
          displayName: rankInfo.displayName,
          color: rankInfo.color
        },
        totalCompleted: user.total_completed_tasks,
        lastActive: user.last_active,
        friendshipStatus: friendship ? friendship.status : null
      };
    });

    res.json({ success: true, users: result });
  } catch (error) {
    if (connection) connection.release();
    console.error('Search users error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.get('/api/community/leaderboard', async (req, res) => {
  let connection;
  try {
    const { limit = 10 } = req.query;
    connection = await pool.getConnection();

    const [users] = await connection.query(
      `SELECT user_id, username, display_name, avatar_url, current_rank, total_completed_tasks
       FROM users WHERE is_public = TRUE
       ORDER BY FIELD(current_rank, 'todo_master', 'platinum', 'diamond', 'gold', 'silver', 'iron'),
                total_completed_tasks DESC LIMIT ?`,
      [parseInt(limit)]
    );

    connection.release();

    const result = users.map((user, index) => {
      const rankInfo = RANK_THRESHOLDS[user.current_rank] || RANK_THRESHOLDS.iron;
      return {
        position: index + 1,
        userId: user.user_id,
        username: user.username,
        displayName: user.display_name,
        avatarUrl: user.avatar_url,
        rank: {
          current: user.current_rank,
          displayName: rankInfo.displayName,
          color: rankInfo.color
        },
        totalCompleted: user.total_completed_tasks
      };
    });

    res.json({ success: true, leaderboard: result });
  } catch (error) {
    if (connection) connection.release();
    console.error('Get leaderboard error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.post('/api/friends/request', verifyToken, async (req, res) => {
  let connection;
  try {
    const { friendId } = req.body;
    if (!friendId) return res.status(400).json({ success: false, message: 'Friend ID required' });
    if (friendId === req.user.userId) return res.status(400).json({ success: false, message: 'Cannot add yourself' });

    connection = await pool.getConnection();
    const [friendUser] = await connection.query('SELECT user_id FROM users WHERE user_id = ?', [friendId]);
    if (friendUser.length === 0) {
      connection.release();
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const [existing] = await connection.query(
      'SELECT friendship_id, status FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)',
      [req.user.userId, friendId, friendId, req.user.userId]
    );

    if (existing.length > 0) {
      connection.release();
      return res.status(409).json({ success: false, message: 'Friendship already exists', status: existing[0].status });
    }

    const friendshipId = `friendship_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    await connection.query(
      'INSERT INTO friendships (friendship_id, user_id, friend_id, status) VALUES (?, ?, ?, ?)',
      [friendshipId, req.user.userId, friendId, 'pending']
    );
    connection.release();

    res.status(201).json({ success: true, message: 'Friend request sent', friendshipId });
  } catch (error) {
    if (connection) connection.release();
    console.error('Send friend request error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.post('/api/friends/accept/:friendshipId', verifyToken, async (req, res) => {
  let connection;
  try {
    const { friendshipId } = req.params;
    connection = await pool.getConnection();

    const [friendships] = await connection.query(
      'SELECT friendship_id, user_id, friend_id, status FROM friendships WHERE friendship_id = ?',
      [friendshipId]
    );

    if (friendships.length === 0) {
      connection.release();
      return res.status(404).json({ success: false, message: 'Friend request not found' });
    }

    const friendship = friendships[0];
    if (friendship.friend_id !== req.user.userId) {
      connection.release();
      return res.status(403).json({ success: false, message: 'Not authorized' });
    }
    if (friendship.status !== 'pending') {
      connection.release();
      return res.status(400).json({ success: false, message: 'Already processed' });
    }

    await connection.query(
      'UPDATE friendships SET status = ?, accepted_at = NOW() WHERE friendship_id = ?',
      ['accepted', friendshipId]
    );

    const reverseFriendshipId = `friendship_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    await connection.query(
      'INSERT INTO friendships (friendship_id, user_id, friend_id, status, accepted_at) VALUES (?, ?, ?, ?, NOW())',
      [reverseFriendshipId, req.user.userId, friendship.user_id, 'accepted']
    );

    connection.release();
    res.json({ success: true, message: 'Friend request accepted' });
  } catch (error) {
    if (connection) connection.release();
    console.error('Accept friend request error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.get('/api/friends', verifyToken, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [friendships] = await connection.query(
      `SELECT u.user_id, u.username, u.display_name, u.avatar_url, u.current_rank, u.total_completed_tasks, u.last_active, f.accepted_at
       FROM friendships f JOIN users u ON f.friend_id = u.user_id
       WHERE f.user_id = ? AND f.status = 'accepted'
       ORDER BY u.total_completed_tasks DESC`,
      [req.user.userId]
    );
    connection.release();

    const friends = friendships.map(friend => {
      const rankInfo = RANK_THRESHOLDS[friend.current_rank] || RANK_THRESHOLDS.iron;
      return {
        userId: friend.user_id,
        username: friend.username,
        displayName: friend.display_name,
        avatarUrl: friend.avatar_url,
        rank: {
          current: friend.current_rank,
          displayName: rankInfo.displayName,
          color: rankInfo.color
        },
        totalCompleted: friend.total_completed_tasks,
        lastActive: friend.last_active,
        friendsSince: friend.accepted_at
      };
    });

    res.json({ success: true, friends });
  } catch (error) {
    if (connection) connection.release();
    console.error('Get friends error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.get('/api/friends/requests', verifyToken, async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();
    const [requests] = await connection.query(
      `SELECT f.friendship_id, u.user_id, u.username, u.display_name, u.avatar_url, u.current_rank, u.total_completed_tasks, f.requested_at
       FROM friendships f JOIN users u ON f.user_id = u.user_id
       WHERE f.friend_id = ? AND f.status = 'pending'
       ORDER BY f.requested_at DESC`,
      [req.user.userId]
    );
    connection.release();

    const result = requests.map(request => {
      const rankInfo = RANK_THRESHOLDS[request.current_rank] || RANK_THRESHOLDS.iron;
      return {
        friendshipId: request.friendship_id,
        userId: request.user_id,
        username: request.username,
        displayName: request.display_name,
        avatarUrl: request.avatar_url,
        rank: {
          current: request.current_rank,
          displayName: rankInfo.displayName,
          color: rankInfo.color
        },
        totalCompleted: request.total_completed_tasks,
        requestedAt: request.requested_at
      };
    });

    res.json({ success: true, requests: result });
  } catch (error) {
    if (connection) connection.release();
    console.error('Get friend requests error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.delete('/api/friends/:friendId', verifyToken, async (req, res) => {
  let connection;
  try {
    const { friendId } = req.params;
    connection = await pool.getConnection();
    await connection.query(
      'DELETE FROM friendships WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)',
      [req.user.userId, friendId, friendId, req.user.userId]
    );
    connection.release();
    res.json({ success: true, message: 'Friend removed' });
  } catch (error) {
    if (connection) connection.release();
    console.error('Remove friend error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

process.on('SIGTERM', async () => {
  await pool.end();
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`✓ Auth service with social features running on port ${PORT}`);
});

module.exports = app;
