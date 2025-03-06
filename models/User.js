// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: String,
    password: String // NOTE: Use hashed passwords in production.
});

module.exports = mongoose.model('User', userSchema);
