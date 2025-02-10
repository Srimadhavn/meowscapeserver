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
const CLIENT_URL = process.env.CLIENT_URL || "https://meowscape.netlify.app";
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/lovechat";

// Basic middleware setup
app.use(express.json());
app.use(cors({
  origin: ['http://localhost:3000', 'https://meowscapeserver.onrender.com','https://meowscape.netlify.app'],
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
    origin: ['http://localhost:3000', 'https://meowscapeserver.onrender.com','https://meowscape.netlify.app'],
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

// Add security middleware at the top of your app configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", 'wss:', 'https:', process.env.CLIENT_URL],
      imgSrc: ["'self'", 'data:', 'blob:', 'https:', process.env.CLIENT_URL, 'https://res.cloudinary.com'],
      mediaSrc: ["'self'", 'data:', 'blob:', 'https:', process.env.CLIENT_URL, 'https://res.cloudinary.com'],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply rate limiting to all routes
app.use(limiter);

// Specific stricter rate limit for authentication routes
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 attempts per hour
  message: 'Too many login attempts, please try again later'
});

app.use('/api/login', authLimiter);

// Add request validation middleware
const validateRequest = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }
    next();
  };
};

// Sanitize file names
const sanitizeFilename = (filename) => {
  return filename.replace(/[^a-zA-Z0-9.-]/g, '_');
};

// Update upload configurations with better security
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join('uploads', 'images');
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const sanitizedName = sanitizeFilename(file.originalname);
    const ext = path.extname(sanitizedName).toLowerCase() || '.jpg';
    cb(null, `image-${uniqueSuffix}${ext}`);
  }
});

// Enhanced error handling for file uploads
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'image/heic',
      'image/heif'
    ];
    
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('Invalid file type'), false);
    }

    if (file.size > 20 * 1024 * 1024) {
      return cb(new Error('File too large'), false);
    }

    cb(null, true);
  },
  limits: {
    fileSize: 20 * 1024 * 1024,
    files: 1
  }
}).single('image');

// Enhanced error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method,
    ip: req.ip
  });

  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      message: 'File upload error',
      error: err.message
    });
  }

  if (err.name === 'ValidationError') {
    return res.status(400).json({
      message: 'Validation error',
      error: err.message
    });
  }

  res.status(err.status || 500).json({
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// Cleanup temporary files periodically
const cleanupTempFiles = () => {
  const tempDirs = ['uploads/images', 'uploads/audio', 'uploads/videos'];
  const maxAge = 24 * 60 * 60 * 1000; // 24 hours

  tempDirs.forEach(dir => {
    if (fs.existsSync(dir)) {
      fs.readdir(dir, (err, files) => {
        if (err) {
          console.error(`Error reading directory ${dir}:`, err);
          return;
        }

        files.forEach(file => {
          const filePath = path.join(dir, file);
          fs.stat(filePath, (err, stats) => {
            if (err) {
              console.error(`Error getting file stats for ${filePath}:`, err);
              return;
            }

            if (Date.now() - stats.mtime.getTime() > maxAge) {
              fs.unlink(filePath, err => {
                if (err) {
                  console.error(`Error deleting file ${filePath}:`, err);
                }
              });
            }
          });
        });
      });
    }
  });
};

// Run cleanup every 6 hours
setInterval(cleanupTempFiles, 6 * 60 * 60 * 1000);

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Performing graceful shutdown...');
  server.close(() => {
    console.log('Server closed');
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  // Attempt to close server gracefully
  server.close(() => {
    console.log('Server closed due to uncaught exception');
    process.exit(1);
  });
  
  // If server hasn't closed in 30 seconds, force shutdown
  setTimeout(() => {
    console.error('Could not close server gracefully, forcing shutdown');
    process.exit(1);
  }, 30000);
});

// Unhandled rejection handler
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  // Log but don't crash the server
});

// Memory usage monitoring
setInterval(() => {
  const used = process.memoryUsage();
  console.log('Memory usage:', {
    rss: `${Math.round(used.rss / 1024 / 1024)}MB`,
    heapTotal: `${Math.round(used.heapTotal / 1024 / 1024)}MB`,
    heapUsed: `${Math.round(used.heapUsed / 1024 / 1024)}MB`,
    external: `${Math.round(used.external / 1024 / 1024)}MB`
  });
}, 30 * 60 * 1000); // Every 30 minutes

// Enable CORS for the sticker endpoints
app.use('/api/stickers', cors({
  origin: ['http://localhost:3000', 'https://meowscapeserver.onrender.com'],
  credentials: true
}));

// Track typing status
const typingUsers = new Map();

// Near the top with other configurations
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;

webpush.setVapidDetails(
  'mailto:srimadhavan93@gmail.com', 
  VAPID_PUBLIC_KEY,
  VAPID_PRIVATE_KEY
);

// Store push subscriptions
const pushSubscriptions = new Map();

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

    // Handle both image and camera capture MIME types
    const validImageTypes = [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'image/heic',  // iOS camera format
      'image/heif'   // iOS camera format
    ];

    if (!validImageTypes.includes(req.file.mimetype)) {
      console.log('Invalid file type:', req.file.mimetype);
      fs.unlinkSync(req.file.path); // Clean up invalid file
      return res.status(400).json({ message: 'Invalid file type. Please upload a valid image.' });
    }

    console.log('Uploading to Cloudinary...'); // Debug log

    // Enhanced Cloudinary upload with image optimization
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: 'chat-images',
      transformation: [
        { quality: 'auto:good' },
        { fetch_format: 'auto' },
        { width: 2000, crop: 'limit' },  // Increased max width for high-res images
        { angle: "exif" }  // Automatically fix image rotation
      ],
      resource_type: 'auto',
      allowed_formats: ['jpg', 'png', 'gif', 'webp', 'heic', 'heif'],
      format: 'webp'  // Convert all images to WebP for better compression
    }).catch(error => {
      console.error('Cloudinary upload error:', error);
      throw new Error('Failed to upload to Cloudinary');
    });

    // Clean up the local file after successful upload
    fs.unlinkSync(req.file.path);

    console.log('Cloudinary upload successful:', result.secure_url); // Debug log

    // Return additional image metadata
    res.json({ 
      url: result.secure_url,
      type: 'image',
      width: result.width,
      height: result.height,
      format: result.format,
      size: result.bytes,
      original_filename: req.file.originalname
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

// Updated audio upload endpoint
app.post('/api/upload-audio', audioUpload.single('audio'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No audio file uploaded' });
    }

    console.log('Uploading audio file:', req.file);

    // Make sure the uploads directory exists
    if (!fs.existsSync('uploads/audio')) {
      fs.mkdirSync('uploads/audio', { recursive: true });
    }

    // Upload to Cloudinary with enhanced configuration
    try {
      const result = await cloudinary.uploader.upload(req.file.path, {
        resource_type: 'video', // Cloudinary uses 'video' type for audio
        folder: 'chat-audio',
        format: 'mp3', // Convert to MP3 for better compatibility
        audio_codec: 'mp3',
        bit_rate: '128k',
        transformation: [
          { audio_frequency: 44100 },
          { audio_sample_rate: '44100' }
        ]
      });

      // Clean up the temporary file
      try {
        fs.unlinkSync(req.file.path);
      } catch (unlinkError) {
        console.error('Error deleting temp file:', unlinkError);
      }

      res.json({ 
        url: result.secure_url,
        type: 'audio',
        format: 'mp3',
        duration: result.duration
      });

    } catch (cloudinaryError) {
      console.error('Cloudinary upload error:', cloudinaryError);
      if (req.file && req.file.path) {
        try {
          fs.unlinkSync(req.file.path);
        } catch (unlinkError) {
          console.error('Error deleting temp file:', unlinkError);
        }
      }
      throw new Error('Failed to upload to Cloudinary: ' + cloudinaryError.message);
    }

  } catch (error) {
    console.error('Audio upload error:', error);
    // Ensure file cleanup on error
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
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

// Handle message deletion by marking it as deleted instead of removing from the database
socket.on('deleteMessage', async ({ messageId, username }) => {
  try {
    console.log(`🔄 Delete request received for messageId: ${messageId} by user: ${username}`);

    // Atomically find and update the message to mark it as deleted
    const message = await Message.findOneAndUpdate(
      { _id: messageId, username }, // Ensure the user owns the message
      { type: 'deleted', text: 'This message was deleted' },
      { new: true } // Return the updated document
    );

    if (!message) {
      console.log(`🚫 Message not found or unauthorized for deletion. messageId: ${messageId}, username: ${username}`);
      socket.emit('deleteError', { message: 'Message not found or unauthorized to delete.' });
      return;
    }

    // Emit messageDeleted event to all connected clients with the messageId
    io.emit('messageDeleted', { messageId: message._id });
    console.log(`Message deleted: ${messageId}`);
  } catch (error) {
    console.error('Error deleting message:', error);
    socket.emit('deleteError', { message: 'Failed to delete message.' });
  }
});

  socket.on('disconnect', () => {
    typingUsers.delete(socket.id);
    socket.broadcast.emit('userTyping', Array.from(typingUsers.values()));
    console.log('User disconnected:', socket.id);
  });

  const MESSAGES_PER_PAGE = 100000000;

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
    const messages = await Message.find()
      .sort({ timestamp: -1 })
      .limit(100000000)
      .lean();

    res.json({
      messages: messages.reverse(),
      hasMore: false
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
