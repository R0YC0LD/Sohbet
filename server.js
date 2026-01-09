/**
 * R0YCHAT - Backend Server
 * Tech: Node.js, Express, Socket.io, SQLite3, Bcrypt
 */
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// --- Middleware ---
const sessionMiddleware = session({
    secret: 'r0ychat-secret-key-change-this',
    resave: false,
    saveUninitialized: false
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(sessionMiddleware);

// Share session with Socket.io
io.use((socket, next) => {
    sessionMiddleware(socket.request, {}, next);
});

// --- Database Setup (SQLite) ---
const db = new sqlite3.Database('./r0ychat.db', (err) => {
    if (err) console.error("DB Error:", err.message);
    else console.log("Connected to SQLite database.");
});

// Initialize Tables
db.serialize(() => {
    // Users
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        avatar TEXT
    )`);

    // Friend Requests
    db.run(`CREATE TABLE IF NOT EXISTS friend_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        receiver_id INTEGER,
        status TEXT DEFAULT 'pending',
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
    )`);

    // Friendships (Bi-directional via two rows or logic, here simplified to distinct pairs)
    db.run(`CREATE TABLE IF NOT EXISTS friendships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        friend_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(friend_id) REFERENCES users(id)
    )`);

    // Messages
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        receiver_id INTEGER,
        content TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// --- Active User Map (UserId -> SocketId) ---
const onlineUsers = new Map();

// --- HTTP Routes (Auth & API) ---

// Register
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Fields required" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const avatar = `https://api.dicebear.com/7.x/identicon/svg?seed=${username}`;

    db.run(`INSERT INTO users (username, password, avatar) VALUES (?, ?, ?)`, 
        [username, hashedPassword, avatar], 
        function(err) {
            if (err) return res.status(400).json({ error: "Username already exists" });
            req.session.userId = this.lastID;
            req.session.username = username;
            req.session.avatar = avatar;
            res.json({ success: true, user: { id: this.lastID, username, avatar } });
        }
    );
});

// Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        if (err || !user) return res.status(400).json({ error: "User not found" });

        const match = await bcrypt.compare(password, user.password);
        if (match) {
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.avatar = user.avatar;
            res.json({ success: true, user: { id: user.id, username: user.username, avatar: user.avatar } });
        } else {
            res.status(400).json({ error: "Invalid password" });
        }
    });
});

// Check Session
app.get('/me', (req, res) => {
    if (req.session.userId) {
        res.json({ loggedIn: true, user: { id: req.session.userId, username: req.session.username, avatar: req.session.avatar } });
    } else {
        res.json({ loggedIn: false });
    }
});

// Logout
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Search Users (for friend requests)
app.get('/search-users', (req, res) => {
    const myId = req.session.userId;
    if (!myId) return res.status(401).json([]);
    const query = req.query.q;
    
    // Find users NOT me, NOT already friends, NOT already requested
    const sql = `
        SELECT id, username, avatar FROM users 
        WHERE username LIKE ? AND id != ?
        AND id NOT IN (SELECT friend_id FROM friendships WHERE user_id = ?)
        AND id NOT IN (SELECT receiver_id FROM friend_requests WHERE sender_id = ?)
        AND id NOT IN (SELECT sender_id FROM friend_requests WHERE receiver_id = ?)
    `;
    db.all(sql, [`%${query}%`, myId, myId, myId, myId], (err, rows) => {
        res.json(rows || []);
    });
});

// Get Friend Requests
app.get('/friend-requests', (req, res) => {
    const myId = req.session.userId;
    if (!myId) return res.status(401);

    const sql = `
        SELECT fr.id as requestId, u.id as userId, u.username, u.avatar 
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = ? AND fr.status = 'pending'
    `;
    db.all(sql, [myId], (err, rows) => {
        res.json(rows || []);
    });
});

// Send Friend Request
app.post('/send-request', (req, res) => {
    const myId = req.session.userId;
    const { receiverId } = req.body;
    
    if(!myId) return res.status(401);

    db.run(`INSERT INTO friend_requests (sender_id, receiver_id) VALUES (?, ?)`, [myId, receiverId], function(err) {
        if(err) return res.status(500).json({error: "Database error"});
        
        // **REAL-TIME NOTIFICATION**
        const receiverSocket = onlineUsers.get(parseInt(receiverId));
        if (receiverSocket) {
            io.to(receiverSocket).emit('new_friend_request', {
                requestId: this.lastID,
                sender: { id: myId, username: req.session.username, avatar: req.session.avatar }
            });
        }
        res.json({ success: true });
    });
});

// Handle Request (Accept/Decline)
app.post('/handle-request', (req, res) => {
    const myId = req.session.userId;
    const { requestId, action, senderId } = req.body; // action: 'accept' or 'decline'

    if (action === 'accept') {
        // Create friendship (bi-directional insert)
        db.serialize(() => {
            db.run(`INSERT INTO friendships (user_id, friend_id) VALUES (?, ?)`, [myId, senderId]);
            db.run(`INSERT INTO friendships (user_id, friend_id) VALUES (?, ?)`, [senderId, myId]);
            db.run(`DELETE FROM friend_requests WHERE id = ?`, [requestId]);
        });

        // Notify Sender
        const senderSocket = onlineUsers.get(parseInt(senderId));
        if(senderSocket) {
            io.to(senderSocket).emit('friend_request_accepted', { 
                newFriend: { id: myId, username: req.session.username, avatar: req.session.avatar, status: 'online' } 
            });
        }
        res.json({ success: true, newFriendId: senderId }); // Return for frontend update
    } else {
        db.run(`DELETE FROM friend_requests WHERE id = ?`, [requestId]);
        res.json({ success: true });
    }
});

// Get Friends List
app.get('/friends', (req, res) => {
    const myId = req.session.userId;
    if(!myId) return res.status(401);

    db.all(`SELECT u.id, u.username, u.avatar FROM friendships f JOIN users u ON f.friend_id = u.id WHERE f.user_id = ?`, [myId], (err, rows) => {
        // Add online status
        const friendsWithStatus = rows.map(f => ({
            ...f,
            status: onlineUsers.has(f.id) ? 'online' : 'offline'
        }));
        res.json(friendsWithStatus || []);
    });
});

// Get Messages
app.get('/messages/:friendId', (req, res) => {
    const myId = req.session.userId;
    const friendId = req.params.friendId;
    
    const sql = `SELECT * FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) ORDER BY timestamp ASC`;
    db.all(sql, [myId, friendId, friendId, myId], (err, rows) => {
        res.json(rows || []);
    });
});

// --- Socket.io Logic ---
io.on('connection', (socket) => {
    const session = socket.request.session;
    
    if (session && session.userId) {
        const userId = session.userId;
        onlineUsers.set(userId, socket.id);
        
        console.log(`User ${session.username} connected (ID: ${userId})`);
        
        // Broadcast online status to friends
        socket.broadcast.emit('user_status', { userId, status: 'online' });

        // Join Room
        socket.on('join_chat', (friendId) => {
            const roomId = [userId, friendId].sort().join('_');
            socket.join(roomId);
        });

        // Send Message
        socket.on('send_message', (data) => {
            const { receiverId, content } = data;
            const timestamp = new Date().toISOString();

            // Save to DB
            db.run(`INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)`, 
                [userId, receiverId, content], (err) => {
                    if(!err) {
                        // Emit to Receiver if online
                        const receiverSocket = onlineUsers.get(parseInt(receiverId));
                        if(receiverSocket) {
                            io.to(receiverSocket).emit('receive_message', {
                                sender_id: userId,
                                content,
                                timestamp
                            });
                        }
                        // Emit back to sender (confirm sent)
                        socket.emit('receive_message', { // Or handle purely optimistically
                           sender_id: userId, // indicates 'me'
                           content,
                           timestamp
                        });
                    }
                }
            );
        });

        // Typing
        socket.on('typing', (data) => {
            const receiverSocket = onlineUsers.get(parseInt(data.receiverId));
            if(receiverSocket) io.to(receiverSocket).emit('display_typing', { senderId: userId });
        });

        socket.on('disconnect', () => {
            onlineUsers.delete(userId);
            socket.broadcast.emit('user_status', { userId, status: 'offline' });
        });
    }
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`R0YCHAT running on http://localhost:${PORT}`);
});
          
