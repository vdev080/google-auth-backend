const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, unique: true, required: true },
    username: { type: String, unique: true, sparse: true }, // `sparse: true` allows multiple `null`
    profileImage: String
});

module.exports = mongoose.model("User", userSchema);
