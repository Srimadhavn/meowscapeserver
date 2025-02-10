const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true
  },
  text: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ['text', 'image', 'sticker', 'audio', 'video'],
    default: 'text'
  },
  timestamp: {
    type: Date,
    default: Date.now
  },
  replyTo: {
    id: {
      type: String
    },
    username: {
      type: String
    },
    text: {
      type: String
    },
    type: {
      type: String
    }
  }
});

module.exports = mongoose.model('Message', messageSchema);
