const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    profileImage: { type: String }, // Store Google profile picture URL
});

const User = mongoose.model("User", userSchema);

module.exports = User;
