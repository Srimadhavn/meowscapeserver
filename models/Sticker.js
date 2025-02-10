const mongoose = require('mongoose');

const stickerSchema = new mongoose.Schema({
  imageUrl: { type: String, required: true },
  packName: { type: String, required: true },
  createdBy: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Sticker', stickerSchema); 