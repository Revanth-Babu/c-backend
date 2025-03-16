const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

// Initialize express app
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key'; // In production, use environment variable

// Middleware
app.use(cors());
app.use(express.json());

// Create database directory if it doesn't exist
const dbDir = path.join(__dirname, 'db');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir);
}

// Set up SQLite database
const db = new sqlite3.Database(path.join(dbDir, 'tasktracker.db'), (err) => {
  if (err) {
    console.error('Error opening database', err.message);
  } else {
    console.log('Connected to the SQLite database');
    initializeDatabase();
  }
});

// Create tables if they don't exist
function initializeDatabase() {
  db.serialize(() => {
    // Create users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      )
    `, (err) => {
      if (err) {
        console.error('Error creating users table', err.message);
      } else {
        console.log('Users table created or already exists');
      }
    });

    // Create tasks table
    db.run(`
      CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT DEFAULT 'Pending' CHECK(status IN ('Pending', 'In Progress', 'Completed')),
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        due_date TEXT,
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `, (err) => {
      if (err) {
        console.error('Error creating tasks table', err.message);
      } else {
        console.log('Tasks table created or already exists');
      }
    });
  });
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    req.user = user;
    next();
  });
}

// API Routes

// Register a new user
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Check if email already exists
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      if (row) {
        return res.status(409).json({ error: 'Email already registered' });
      }

      // Insert new user
      const sql = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
      db.run(sql, [name, email, hashedPassword], function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        // Generate JWT token
        const token = jwt.sign({ id: this.lastID, email, name }, JWT_SECRET, { expiresIn: '24h' });
        res.status(201).json({ 
          message: 'User registered successfully',
          userId: this.lastID,
          name,
          token
        });
      });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login user
app.post('/login', (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user by email
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Compare password
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Generate JWT token
      const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
      res.json({ 
        message: 'Login successful', 
        userId: user.id,
        name: user.name,
        token 
      });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Fix: Move the search endpoint BEFORE the :id endpoint to avoid routing conflict
// BONUS: Search and filter tasks
app.get('/tasks/search', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const { query, status } = req.query;
  
  let sql = 'SELECT * FROM tasks WHERE user_id = ?';
  let params = [userId];
  
  if (query) {
    sql += ' AND (title LIKE ? OR description LIKE ?)';
    params.push(`%${query}%`, `%${query}%`);
  }
  
  if (status) {
    sql += ' AND status = ?';
    params.push(status);
  }
  
  sql += ' ORDER BY created_at DESC';
  
  db.all(sql, params, (err, tasks) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    // Fix: Return an array instead of an object with tasks property
    res.json(tasks);
  });
});

// Get all tasks for a user
app.get('/tasks', authenticateToken, (req, res) => {
  const userId = req.user.id;
  
  db.all('SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, tasks) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    // Fix: Return an array instead of an object with tasks property
    res.json(tasks);
  });
});

// Get a specific task
app.get('/tasks/:id', authenticateToken, (req, res) => {
  const taskId = req.params.id;
  const userId = req.user.id;

  db.get('SELECT * FROM tasks WHERE id = ? AND user_id = ?', [taskId, userId], (err, task) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }
    
    // Fix: Return task directly instead of wrapping in object
    res.json(task);
  });
});

// Create a new task
app.post('/tasks', authenticateToken, (req, res) => {
  try {
    const { title, description, due_date, status } = req.body;
    const userId = req.user.id;

    if (!title) {
      return res.status(400).json({ error: 'Task title is required' });
    }

    const taskStatus = status || 'Pending';
    
    const sql = 'INSERT INTO tasks (title, description, due_date, status, user_id) VALUES (?, ?, ?, ?, ?)';
    db.run(sql, [title, description, due_date, taskStatus, userId], function(err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      
      // Get the inserted task to return
      db.get('SELECT * FROM tasks WHERE id = ?', [this.lastID], (err, task) => {
        if (err) {
          return res.status(500).json({ error: err.message });
        }
        // Fix: Return task directly instead of wrapping in object
        res.status(201).json(task);
      });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update a task
app.put('/tasks/:id', authenticateToken, (req, res) => {
  try {
    const taskId = req.params.id;
    const userId = req.user.id;
    const { title, description, status, due_date } = req.body;

    // First check if the task exists and belongs to the user
    db.get('SELECT * FROM tasks WHERE id = ? AND user_id = ?', [taskId, userId], (err, task) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (!task) {
        return res.status(404).json({ error: 'Task not found or unauthorized' });
      }

      // Update task
      const sql = `
        UPDATE tasks 
        SET title = COALESCE(?, title),
            description = COALESCE(?, description),
            status = COALESCE(?, status),
            due_date = COALESCE(?, due_date)
        WHERE id = ? AND user_id = ?
      `;
      
      db.run(sql, [title, description, status, due_date, taskId, userId], function(err) {
        if (err) {
          return res.status(500).json({ error: err.message });
        }

        if (this.changes === 0) {
          return res.status(404).json({ error: 'Task not updated' });
        }

        // Get the updated task
        db.get('SELECT * FROM tasks WHERE id = ?', [taskId], (err, updatedTask) => {
          if (err) {
            return res.status(500).json({ error: err.message });
          }
          // Fix: Return updated task directly
          res.json(updatedTask);
        });
      });
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete a task
app.delete('/tasks/:id', authenticateToken, (req, res) => {
  const taskId = req.params.id;
  const userId = req.user.id;

  db.run('DELETE FROM tasks WHERE id = ? AND user_id = ?', [taskId, userId], function(err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Task not found or unauthorized' });
    }

    res.json({ message: 'Task deleted successfully', id: taskId });
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;