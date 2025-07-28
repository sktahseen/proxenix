const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Store connected users for better socket management
const connectedUsers = new Map();

// Configure multer for image uploads
const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5000000 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb('Error: Images only (jpeg, jpg, png, gif)!');
  }
});

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use('/styles', express.static('styles'));
app.use('/uploads', express.static('uploads'));

// Connect to MongoDB
mongoose.connect('mongodb://localhost/ChatApp', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  otp: String,
  otpExpiration: Date,
  status: { type: String, default: 'Hey there! I am using ChatApp' },
  lastSeen: { type: Date, default: Date.now },
  online: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// Message Schema (improved with better indexing)
const messageSchema = new mongoose.Schema({
  user: { type: String, required: true },
  recipient: String, // null for group messages
  text: String,
  imagePath: String,
  messageType: { type: String, enum: ['text', 'image'], default: 'text' },
  timestamp: { type: Date, default: Date.now },
});

// Add indexes for better query performance
messageSchema.index({ timestamp: 1 });
messageSchema.index({ user: 1, recipient: 1 });
messageSchema.index({ recipient: 1 });

const Message = mongoose.model('Message', messageSchema);

// Nodemailer setup
const transporter = nodemailer.createTransporter({
  service: 'Gmail',
  auth: {
    user: 'tahseensyed685@gmail.com',
    pass: 'vqxt arht poad jwar',
  },
});

// Password validation function
const validatePassword = (password) => {
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$/;
  return passwordRegex.test(password);
};

// Routes
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.get('/', (req, res) => {
  res.render('login', { error: null });
});

app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    if (!validatePassword(password)) {
      return res.render('register', {
        error: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character (!@#$%^&*).',
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, email, password: hashedPassword });
    await user.save();
    console.log('User registered:', email);
    res.redirect('/');
  } catch (err) {
    console.error('Registration error:', err.message);
    if (err.code === 11000) {
      res.render('register', { error: 'Email already exists. Please use a different email.' });
    } else {
      res.render('register', { error: 'Registration failed. Please try again.' });
    }
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
        return res.status(401).json({ error: 'No account found with this email.' });
      }
      return res.render('login', { error: 'No account found with this email.' });
    }
    if (await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ email: user.email, username: user.username }, 'secretkey');
      res.cookie('token', token, { httpOnly: true });
      await User.updateOne({ email }, { online: true, lastSeen: Date.now() });
      if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
        return res.status(200).json({ redirect: '/chat' });
      }
      res.redirect('/chat');
    } else {
      if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
        return res.status(401).json({ error: 'Incorrect password. Please try again.' });
      }
      res.render('login', { error: 'Incorrect password. Please try again.' });
    }
  } catch (err) {
    console.error('Login error:', err.message);
    if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
      return res.status(500).json({ error: 'Login failed. Please try again.' });
    }
    res.render('login', { error: 'Login failed. Please try again.' });
  }
});

// Fixed route for group chat - load only group messages (no recipient)
app.get('/chat', async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/');
  }
  try {
    const decoded = jwt.verify(token, 'secretkey');
    // Load only group messages (messages without recipient)
    const messages = await Message.find({ 
      recipient: { $exists: false } 
    }).sort({ timestamp: 1 }).limit(100); // Limit to last 100 messages for performance
    
    const users = await User.find({}, 'username status online lastSeen');
    res.render('chat', { username: decoded.username, messages, users, recipient: null });
  } catch (err) {
    console.log('Token verification failed:', err.message);
    res.redirect('/');
  }
});

// Fixed route for private chats - load only private messages between two users
app.get('/chat/:recipient', async (req, res) => {
  const token = req.cookies.token;
  const recipient = req.params.recipient;
  if (!token) {
    return res.redirect('/');
  }
  try {
    const decoded = jwt.verify(token, 'secretkey');
    // Load only private messages between current user and recipient
    const messages = await Message.find({
      $and: [
        { recipient: { $exists: true, $ne: null } }, // Only private messages
        {
          $or: [
            { user: decoded.username, recipient: recipient },
            { user: recipient, recipient: decoded.username }
          ]
        }
      ]
    }).sort({ timestamp: 1 }).limit(100); // Limit to last 100 messages for performance
    
    const users = await User.find({}, 'username status online lastSeen');
    res.render('chat', { username: decoded.username, messages, users, recipient });
  } catch (err) {
    console.log('Token verification failed:', err.message);
    res.redirect('/');
  }
});

// Update user status
app.post('/update-status', async (req, res) => {
  const { status } = req.body;
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const decoded = jwt.verify(token, 'secretkey');
    await User.updateOne({ email: decoded.email }, { status });
    io.emit('status update', { username: decoded.username, status });
    res.json({ success: true });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Fixed image upload route
app.post('/upload-image', upload.single('image'), async (req, res) => {
  const token = req.cookies.token;
  const { recipient } = req.body;
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const decoded = jwt.verify(token, 'secretkey');
    const imagePath = `/uploads/${req.file.filename}`;
    const message = new Message({
      user: decoded.username,
      recipient: recipient || undefined, // Use undefined instead of null for group chat
      imagePath,
      messageType: 'image',
      timestamp: new Date()
    });
    await message.save();
    
    // Emit to appropriate recipients
    if (recipient) {
      // Private message - send to recipient and sender
      const recipientSocketId = connectedUsers.get(recipient);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('chat message', message);
      }
      const senderSocketId = connectedUsers.get(decoded.username);
      if (senderSocketId) {
        io.to(senderSocketId).emit('chat message', message);
      }
    } else {
      // Group message - broadcast to all
      io.emit('chat message', message);
    }
    
    res.json({ success: true, imagePath });
  } catch (err) {
    console.error('Image upload error:', err.message);
    res.status(500).json({ error: 'Image upload failed' });
  }
});

// Forgot Password Routes
app.get('/forgot-password', (req, res) => {
  res.render('forgot-password', { error: null });
});

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.render('forgot-password', { error: 'No account found with this email.' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp;
    user.otpExpiration = Date.now() + 600000;
    await user.save();

    await transporter.sendMail({
      to: email,
      from: 'tahseensyed685@gmail.com',
      subject: 'Password Reset OTP',
      html: `<p>Your OTP for password reset is: <strong>${otp}</strong></p><p>This OTP is valid for 10 minutes.</p>`,
    });

    res.redirect('/reset-password');
  } catch (err) {
    console.error('Forgot password error:', err.message);
    res.render('forgot-password', { error: 'Failed to send OTP. Please try again.' });
  }
});

app.get('/reset-password', (req, res) => {
  res.render('reset-password', { error: null });
});

app.post('/reset-password', async (req, res) => {
  const { email, otp, password } = req.body;
  try {
    if (!validatePassword(password)) {
      return res.render('reset-password', {
        error: 'Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character (!@#$%^&*).',
      });
    }

    const user = await User.findOne({
      email,
      otp,
      otpExpiration: { $gt: Date.now() },
    });
    if (!user) {
      return res.render('reset-password', { error: 'Invalid or expired OTP. Please try again.' });
    }

    user.password = await bcrypt.hash(password, 10);
    user.otp = undefined;
    user.otpExpiration = undefined;
    await user.save();

    res.redirect('/');
  } catch (err) {
    console.error('Reset password error:', err.message);
    res.render('reset-password', { error: 'Password reset failed. Please try again.' });
  }
});

// Add logout route
app.post('/logout', async (req, res) => {
  const token = req.cookies.token;
  if (token) {
    try {
      const decoded = jwt.verify(token, 'secretkey');
      await User.updateOne({ email: decoded.email }, { online: false, lastSeen: Date.now() });
      connectedUsers.delete(decoded.username);
    } catch (err) {
      console.error('Logout error:', err.message);
    }
  }
  res.clearCookie('token');
  res.redirect('/');
});

// Socket.io middleware for authentication
io.use((socket, next) => {
  const token = socket.handshake.query.token;
  if (token) {
    try {
      const decoded = jwt.verify(token, 'secretkey');
      socket.userId = decoded.username;
      socket.userEmail = decoded.email;
      next();
    } catch (err) {
      next(new Error('Authentication error'));
    }
  } else {
    next(new Error('Authentication error'));
  }
});

// Improved Socket.io for real-time chat
io.on('connection', async (socket) => {
  console.log(`User ${socket.userId} connected`);
  
  // Store the connection
  connectedUsers.set(socket.userId, socket.id);
  
  // Update user online status
  try {
    await User.updateOne({ username: socket.userId }, { online: true, lastSeen: Date.now() });
    io.emit('status update', { username: socket.userId, online: true });
  } catch (err) {
    console.error('Error updating user status:', err.message);
  }

  // Handle chat messages
  socket.on('chat message', async (msg) => {
    try {
      const message = new Message({
        user: msg.user,
        recipient: msg.recipient || undefined, // Use undefined for group chat
        text: msg.text,
        messageType: 'text',
        timestamp: new Date()
      });
      await message.save();
      
      if (msg.recipient) {
        // Private message
        const recipientSocketId = connectedUsers.get(msg.recipient);
        if (recipientSocketId) {
          io.to(recipientSocketId).emit('chat message', message);
        }
        // Also send to sender
        io.to(socket.id).emit('chat message', message);
      } else {
        // Group message - broadcast to all
        io.emit('chat message', message);
      }
    } catch (err) {
      console.error('Error saving message to DB:', err.message);
    }
  });

  // Handle emoji reactions
  socket.on('emoji reaction', (data) => {
    if (data.recipient) {
      const recipientSocketId = connectedUsers.get(data.recipient);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('emoji reaction', data);
      }
      io.to(socket.id).emit('emoji reaction', data);
    } else {
      io.emit('emoji reaction', data);
    }
  });

  // Handle typing indicators
  socket.on('typing', (data) => {
    if (data.recipient) {
      const recipientSocketId = connectedUsers.get(data.recipient);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('typing', data);
      }
    } else {
      socket.broadcast.emit('typing', data);
    }
  });

  socket.on('stop typing', (data) => {
    if (data.recipient) {
      const recipientSocketId = connectedUsers.get(data.recipient);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('stop typing', data);
      }
    } else {
      socket.broadcast.emit('stop typing', data);
    }
  });

  // Handle disconnect
  socket.on('disconnect', async () => {
    console.log(`User ${socket.userId} disconnected`);
    connectedUsers.delete(socket.userId);
    
    try {
      await User.updateOne({ username: socket.userId }, { online: false, lastSeen: Date.now() });
      io.emit('status update', { username: socket.userId, online: false });
    } catch (err) {
      console.error('Disconnect error:', err.message);
    }
  });
});

server.listen(3000, () => console.log('Server running on port 3000'));
