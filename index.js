const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const Message = require('./models/Message');
const User = require('./models/User');
const bcrypt = require('bcrypt');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const Sticker = require('./models/Sticker');
const ffmpeg = require('fluent-ffmpeg');
const path = require('path');
const fs = require('fs');

dotenv.config();

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/lovechat";

// Basic middleware setup
app.use(express.json());
app.use(cors({
  origin: '*', // During development, accept all origins
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: true
}));

// Health check endpoint - MUST be before other routes
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok',
    timestamp: new Date(),
    uptime: process.uptime(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Socket.IO setup with CORS
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ["GET", "POST"],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  }
});

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
  .then(() => console.log('MongoDB connected successfully'))
  .catch((err) => console.error('MongoDB connection failed:', err));

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// First, define the storage configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let uploadPath = 'uploads/';
    if (file.mimetype.startsWith('video/')) {
      uploadPath = path.join(uploadPath, 'videos');
    } else if (file.mimetype.startsWith('image/')) {
      uploadPath = path.join(uploadPath, 'images');
    } else if (file.mimetype.startsWith('audio/')) {
      uploadPath = path.join(uploadPath, 'audio');
    } else {
      uploadPath = path.join(uploadPath, 'files');
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

// Create necessary directories
const uploadsDir = 'uploads';
const imagesDir = path.join(uploadsDir, 'images');
const videosDir = path.join(uploadsDir, 'videos');
const audioDir = path.join(uploadsDir, 'audio');
const filesDir = path.join(uploadsDir, 'files');

// Create directories if they don't exist
[uploadsDir, imagesDir, videosDir, audioDir, filesDir].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Then configure multer with the storage
const upload = multer({
  storage,
  limits: {
    fileSize: 100 * 1024 * 1024 // 100MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      // Images
      'image/jpeg', 'image/png', 'image/gif',
      // Videos
      'video/mp4', 'video/quicktime', 'video/x-msvideo',
      // Audio
      'audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/ogg', 'audio/webm',
      // Documents
      'application/pdf',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/vnd.ms-powerpoint',
      'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      'text/plain'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'));
    }
  }
});

// Enable CORS for the sticker endpoints
app.use('/api/stickers', cors());

// Track typing status
const typingUsers = new Map();

async function initializeUsers() {
  try {
    const users = [
      { username: 'Maddy', password: 'varsha' },
      { username: 'Varsha', password: 'maddy' }
    ];

    for (const user of users) {
      const existingUser = await User.findOne({ username: user.username });
      if (!existingUser) {
        const hashedPassword = await bcrypt.hash(user.password, 10);
        await User.create({
          username: user.username,
          password: hashedPassword
        });
        console.log(`Created user: ${user.username}`);
      }
    }
  } catch (error) {
    console.error('Error initializing users:', error);
  }
}

initializeUsers();

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log('Login attempt:', { username, password });
    
    const user = await User.findOne({ username });
    console.log('Found user:', user);

    if (!user) {
      console.log('No user found');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    console.log('Password valid:', isValidPassword);
    
    if (!isValidPassword) {
      console.log('Invalid password');
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    res.json({ success: true, username: user.username });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update the sticker endpoints
app.get('/api/stickers', async (req, res) => {
  try {
    // Get custom stickers from MongoDB
    const customStickers = await Sticker.find().lean();
    
    // Group stickers by pack name
    const customPacks = customStickers.reduce((acc, sticker) => {
      if (!acc[sticker.packName]) {
        acc[sticker.packName] = [];
      }
      acc[sticker.packName].push({
        url: sticker.imageUrl,
        id: sticker._id
      });
      return acc;
    }, {});

    // Combine with default emoji packs
    const allStickers = {
      ...customPacks,
      
    };

    console.log('Sending sticker packs:', allStickers);
    res.json(allStickers);
  } catch (error) {
    console.error('Error fetching stickers:', error);
    res.status(500).json({ message: 'Failed to fetch stickers' });
  }
});

// Update sticker upload endpoint
app.post('/api/stickers/upload', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const { packName, username } = req.body;

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: 'stickers',
      resource_type: 'auto'
    });

    // Save to MongoDB
    const sticker = await Sticker.create({
      imageUrl: result.secure_url,
      packName,
      createdBy: username,
      order: await Sticker.countDocuments({ packName }) // Add at the end of the pack
    });

    res.json({
      id: sticker._id,
      url: sticker.imageUrl,
      packName: sticker.packName
    });
  } catch (error) {
    console.error('Error uploading sticker:', error);
    res.status(500).json({ message: 'Failed to upload sticker' });
  }
});

// Add endpoint to reorder stickers within a pack
app.post('/api/stickers/reorder', async (req, res) => {
  try {
    const { packName, stickerId, newOrder } = req.body;
    
    const sticker = await Sticker.findById(stickerId);
    if (!sticker) {
      return res.status(404).json({ message: 'Sticker not found' });
    }

    // Update orders of all affected stickers
    await Sticker.updateMany(
      { 
        packName,
        order: { $gte: newOrder },
        _id: { $ne: stickerId }
      },
      { $inc: { order: 1 } }
    );

    sticker.order = newOrder;
    await sticker.save();

    res.json({ message: 'Sticker reordered successfully' });
  } catch (error) {
    console.error('Error reordering sticker:', error);
    res.status(500).json({ message: 'Failed to reorder sticker' });
  }
});

// Update delete endpoint to match the new folder structure
app.delete('/api/stickers/:stickerId', async (req, res) => {
  try {
    const sticker = await Sticker.findById(req.params.stickerId);
    if (!sticker) {
      return res.status(404).json({ message: 'Sticker not found' });
    }

    // Delete from Cloudinary (now from single folder)
    const publicId = sticker.imageUrl.split('/').slice(-1)[0].split('.')[0];
    await cloudinary.uploader.destroy(`stickers/${publicId}`);

    // Delete from database
    await sticker.deleteOne();

    // Reorder remaining stickers
    await Sticker.updateMany(
      { packName: sticker.packName, order: { $gt: sticker.order } },
      { $inc: { order: -1 } }
    );

    res.json({ message: 'Sticker deleted successfully' });
  } catch (error) {
    console.error('Error deleting sticker:', error);
    res.status(500).json({ message: 'Failed to delete sticker' });
  }
});

// Update the image upload endpoint
app.post('/api/upload-image', upload.single('image'), async (req, res) => {
  try {
    console.log('Received file:', req.file); // Debug log

    if (!req.file) {
      console.log('No file received');
      return res.status(400).json({ message: 'No file uploaded' });
    }

    // Ensure the file is an image
    if (!req.file.mimetype.startsWith('image/')) {
      console.log('Invalid file type:', req.file.mimetype);
      fs.unlinkSync(req.file.path); // Clean up invalid file
      return res.status(400).json({ message: 'Invalid file type. Please upload an image.' });
    }

    console.log('Uploading to Cloudinary...'); // Debug log

    // Upload to Cloudinary with error handling
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: 'chat-images',
      transformation: [
        { quality: 'auto' },
        { fetch_format: 'auto' },
        { width: 1200, crop: 'limit' }
      ],
      resource_type: 'auto'
    }).catch(error => {
      console.error('Cloudinary upload error:', error);
      throw new Error('Failed to upload to Cloudinary');
    });

    // Clean up the local file after successful upload
    fs.unlinkSync(req.file.path);

    console.log('Cloudinary upload successful:', result.secure_url); // Debug log

    res.json({ 
      url: result.secure_url,
      type: 'image'
    });
  } catch (error) {
    console.error('Error in image upload:', error);
    // Clean up the file if it exists and there was an error
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ 
      message: 'Failed to upload image',
      error: error.message 
    });
  }
});

// Add this endpoint to view all stored stickers
app.get('/api/stickers/all', async (req, res) => {
  try {
    const stickers = await Sticker.find().sort({ createdAt: -1 });
    res.json({
      total: stickers.length,
      stickers: stickers.map(s => ({
        id: s._id,
        url: s.imageUrl,
        pack: s.packName,
        uploadedBy: s.createdBy,
        uploadedAt: s.createdAt
      }))
    });
  } catch (error) {
    console.error('Error fetching all stickers:', error);
    res.status(500).json({ message: 'Failed to fetch stickers' });
  }
});

// Add file upload endpoint
app.post('/api/upload-file', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const file = req.file;
    let fileUrl = `${process.env.SERVER_URL}/uploads/`;
    let fileType = 'file';
    let compressedPath = null;

    // Handle video compression
    if (file.mimetype.startsWith('video/')) {
      fileType = 'video';
      const outputPath = `uploads/videos/compressed-${file.filename}`;
      
      await new Promise((resolve, reject) => {
        ffmpeg(file.path)
          .videoCodec('libx264')
          .size('640x?')
          .videoBitrate('800k')
          .audioCodec('aac')
          .audioBitrate('128k')
          .outputOptions(['-movflags faststart'])
          .on('end', () => resolve())
          .on('error', (err) => reject(err))
          .save(outputPath);
      });

      compressedPath = outputPath;
      fileUrl += `videos/compressed-${file.filename}`;
    } else if (file.mimetype.startsWith('image/')) {
      fileType = 'image';
      fileUrl += `images/${file.filename}`;
    } else {
      fileUrl += `files/${file.filename}`;
    }

    // Get file size and name
    const fileSize = file.size;
    const fileName = file.originalname;

    res.json({
      url: fileUrl,
      type: fileType,
      name: fileName,
      size: fileSize
    });

  } catch (error) {
    console.error('Error processing file:', error);
    res.status(500).json({ error: 'Failed to process file' });
  }
});

// Add audio upload endpoint
app.post('/api/upload-audio', upload.single('audio'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No audio file uploaded' });
    }

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: 'chat-audio',
      resource_type: 'video', // Cloudinary uses 'video' type for audio files
      format: 'mp3'
    });

    // Clean up the temporary file
    fs.unlinkSync(req.file.path);

    res.json({ 
      url: result.secure_url,
      type: 'audio'
    });
  } catch (error) {
    console.error('Error uploading audio:', error);
    // Clean up the file if it exists and there was an error
    if (req.file && req.file.path) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ message: 'Failed to upload audio' });
  }
});

io.on('connection', async (socket) => {
  console.log('User connected:', socket.id);

  // Send previous messages on connection
  try {
    const previousMessages = await Message.find()
      .sort({ timestamp: 1 })
      .lean()
      .exec();
    socket.emit('previousMessages', previousMessages);
  } catch (error) {
    console.error('Error fetching previous messages:', error);
  }

  // Handle typing status
  socket.on('typing', (username) => {
    typingUsers.set(socket.id, username);
    socket.broadcast.emit('userTyping', Array.from(typingUsers.values()));
  });

  socket.on('stopTyping', () => {
    typingUsers.delete(socket.id);
    socket.broadcast.emit('userTyping', Array.from(typingUsers.values()));
  });

  // Handle message sending
  socket.on('sendMessage', async (messageData) => {
    try {
      console.log('Received message:', messageData);
      
      const messageObj = {
        username: messageData.username,
        text: messageData.text,
        type: messageData.type,
        timestamp: new Date()
      };

      if (messageData.replyTo) {
        messageObj.replyTo = {
          id: messageData.replyTo._id,
          username: messageData.replyTo.username,
          text: messageData.replyTo.text,
          type: messageData.replyTo.type
        };
      }

      const message = new Message(messageObj);
      const savedMessage = await message.save();
      
      io.emit('message', savedMessage.toObject());
    } catch (error) {
      console.error('Error saving message:', error);
      socket.emit('messageError', { error: 'Failed to send message' });
    }
  });

  // Handle message deletion
  socket.on('deleteMessage', async ({ messageId, username }) => {
    try {
      const message = await Message.findById(messageId);
      if (message && message.username === username) {
        await Message.findByIdAndDelete(messageId);
        io.emit('messageDeleted', messageId);
      }
    } catch (error) {
      console.error('Error deleting message:', error);
      socket.emit('deleteError', 'Failed to delete message');
    }
  });

  socket.on('disconnect', () => {
    typingUsers.delete(socket.id);
    socket.broadcast.emit('userTyping', Array.from(typingUsers.values()));
    console.log('User disconnected:', socket.id);
  });

  // Update the message fetching endpoint
  const MESSAGES_PER_PAGE = 50;

  socket.on('fetchMessages', async ({ page = 1 }) => {
    try {
      const messages = await Message.find()
        .sort({ timestamp: -1 })
        .skip((page - 1) * MESSAGES_PER_PAGE)
        .limit(MESSAGES_PER_PAGE)
        .lean();

      socket.emit('messages', {
        messages: messages.reverse(),
        page,
        hasMore: messages.length === MESSAGES_PER_PAGE
      });
    } catch (error) {
      console.error('Error fetching messages:', error);
      socket.emit('error', { message: 'Failed to fetch messages' });
    }
  });
});

// Error handling middleware - MUST be after all routes
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    message: 'Internal server error', 
    error: process.env.NODE_ENV === 'development' ? err.message : undefined 
  });
});

// 404 handler - MUST be after all routes
app.use((req, res) => {
  res.status(404).json({ message: 'Not found' });
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

// Global error handling
process.on('unhandledRejection', (error) => {
  console.error('Unhandled promise rejection:', error);
});

module.exports = app;
