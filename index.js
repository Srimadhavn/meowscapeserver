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
const webpush = require('web-push');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');

dotenv.config();

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 5000;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:3000";
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/lovechat";

// Basic middleware setup
app.use(express.json());
app.use(cors({
  origin: ['http://localhost:3000', 'https://meowscapeserver.onrender.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  credentials: true
}));

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date(),
    memory: process.memoryUsage()
  });
});

const io = new Server(server, {
  cors: {
    origin: ['http://localhost:3000', 'https://meowscapeserver.onrender.com'],
    methods: ["GET", "POST"],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
  }
});

mongoose.connect(process.env.MONGODB_URI || process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
.then(() => {
  console.log('MongoDB connected successfully');
  // Initialize users after successful connection
  initializeUsers();
})
.catch((err) => {
  console.error('MongoDB connection failed:', err);
  process.exit(1);
});

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
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

// Configure multer specifically for audio uploads
const audioUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = 'uploads/audio';
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      cb(null, uniqueSuffix + '.webm');
    }
  }),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'audio/webm' || file.mimetype.startsWith('audio/')) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only audio files are allowed.'));
    }
  }
});

// Enable CORS for the sticker endpoints
app.use('/api/stickers', cors({
  origin: ['http://localhost:3000', 'https://meowscapeserver.onrender.com'],
  credentials: true
}));

// Track typing status
const typingUsers = new Map();

// Generate VAPID keys using webpush.generateVAPIDKeys()
const vapidKeys = webpush.generateVAPIDKeys();
console.log(vapidKeys);
// Save these keys in your .env file

// Store push subscriptions
const pushSubscriptions = new Map();

// Add near the top after dotenv.config()
webpush.setVapidDetails(
  'mailto:your@email.com', // Your email
  process.env.VAPID_PUBLIC_KEY,
  process.env.VAPID_PRIVATE_KEY
);

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

    // Check for existing messages
    const messageCount = await Message.countDocuments();
    if (messageCount === 0) {
      await Message.insertMany(initialMessages);
      console.log('Initial messages created');
    }
  } catch (error) {
    console.error('Error initializing data:', error);
  }
}

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
      // Create pack if it doesn't exist
      if (!acc[sticker.packName]) {
        acc[sticker.packName] = [];
      }
      // Add sticker to pack
      acc[sticker.packName].push({
        url: sticker.imageUrl,
        id: sticker._id,
        createdBy: sticker.createdBy // Include creator info
      });
      return acc;
    }, {});

    console.log('Sending sticker packs:', customPacks);
    res.json(customPacks);
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

    // Save to MongoDB with correct username
    const sticker = await Sticker.create({
      imageUrl: result.secure_url,
      packName: packName || 'My Stickers',
      createdBy: username, // This will now be either 'Maddy' or 'Varsha'
      order: await Sticker.countDocuments({ packName })
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

// Audio upload endpoint
app.post('/api/upload-audio', audioUpload.single('audio'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No audio file uploaded' });
    }

    console.log('Uploading audio file:', req.file); // Debug log

    // Make sure the uploads directory exists
    if (!fs.existsSync('uploads/audio')) {
      fs.mkdirSync('uploads/audio', { recursive: true });
    }

    // Upload to Cloudinary with proper error handling
    try {
      const result = await cloudinary.uploader.upload(req.file.path, {
        resource_type: 'video', // Cloudinary uses 'video' type for audio
        folder: 'chat-audio',
        format: 'mp3'
      });

      // Clean up the temporary file
      try {
        fs.unlinkSync(req.file.path);
      } catch (unlinkError) {
        console.error('Error deleting temp file:', unlinkError);
        // Continue even if cleanup fails
      }

      // Send response
      res.json({ 
        url: result.secure_url,
        type: 'audio'
      });

    } catch (cloudinaryError) {
      console.error('Cloudinary upload error:', cloudinaryError);
      // Clean up on cloudinary error
      if (req.file && req.file.path) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (unlinkError) {
          console.error('Error deleting temp file:', unlinkError);
        }
      }
      throw new Error('Failed to upload to Cloudinary');
    }

  } catch (error) {
    console.error('Audio upload error:', error);
    res.status(500).json({ 
      message: 'Failed to upload audio',
      error: error.message 
    });
  }
});

io.on('connection', async (socket) => {
  console.log('User connected:', socket.id);

  // Send previous messages on connection
  try {
    const previousMessages = await Message.find()
      .sort({ timestamp: -1 })
      .limit(50)
      .lean();
    socket.emit('previousMessages', previousMessages.reverse());
  } catch (error) {
    console.error('Error fetching previous messages:', error);
    socket.emit('error', { message: 'Failed to fetch messages' });
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

      // Send notification to other users
      const notification = {
        title: 'New Message from ' + messageData.username,
        body: messageData.type === 'text' ? messageData.text.substring(0, 50) : 'Sent a ' + messageData.type,
        icon: '/icon-192.png',
        badge: '/icon-192.png',
        vibrate: [100, 50, 100]
      };

      const receiverSubscription = pushSubscriptions.get(messageData.to);
      if (receiverSubscription) {
        try {
          await webpush.sendNotification(
            receiverSubscription,
            JSON.stringify(notification)
          );
        } catch (error) {
          console.error('Error sending push notification:', error);
        }
      }
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
        message.text = 'This message was deleted';
        message.isDeleted = true;
        await message.save();
        
        io.emit('messageUpdated', {
          messageId,
          text: 'This message was deleted',
          isDeleted: true
        });
      }
    } catch (error) {
      console.error('Error updating message:', error);
      socket.emit('deleteError', 'Failed to delete message');
    }
  });

  socket.on('disconnect', () => {
    typingUsers.delete(socket.id);
    socket.broadcast.emit('userTyping', Array.from(typingUsers.values()));
    console.log('User disconnected:', socket.id);
  });

  const MESSAGES_PER_PAGE = 1000;

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

app.get('/api/messages', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 10000; 

    const [messages, total] = await Promise.all([
      Message.find()
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit + 1)
        .lean(),
      Message.countDocuments()
    ]);

    const hasMore = messages.length > limit;
    const messagesToSend = hasMore ? messages.slice(0, -1) : messages;

    res.json({
      messages: messagesToSend.reverse(),
      hasMore,
      page,
      total
    });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

app.post('/api/subscribe', async (req, res) => {
  try {
    const { subscription, username } = req.body;
    console.log('New push subscription for:', username);
    pushSubscriptions.set(username, subscription);
    res.status(200).json({ message: 'Successfully subscribed to notifications' });
  } catch (error) {
    console.error('Subscription error:', error);
    res.status(500).json({ error: 'Subscription failed' });
  }
});

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100 
}));

app.use(helmet());
app.use(compression());

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    message: 'Internal server error', 
    error: process.env.NODE_ENV === 'development' ? err.message : undefined 
  });
});

app.use((req, res) => {
  res.status(404).json({ message: 'Not found' });
});

app.use(express.static(path.join(__dirname, '../client/build')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/build', 'index.html'));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

process.on('unhandledRejection', (error) => {
  console.error('Unhandled promise rejection:', error);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

module.exports = app;
