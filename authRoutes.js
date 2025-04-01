const express = require("express");
const passport = require("passport");
const jwt = require("jsonwebtoken");
const User = require("./userModel");
const { google } = require("./config");

const router = express.Router();

// Google OAuth Strategy
const GoogleStrategy = require("passport-google-oauth20").Strategy;
passport.use(new GoogleStrategy({
    clientID: google.clientID,
    clientSecret: google.clientSecret,
    callbackURL: "/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
            user = await User.create({
                googleId: profile.id,
                name: profile.displayName,
                email: profile.emails[0].value,
                picture: profile.photos[0].value
            });
        }

        done(null, user);
    } catch (error) {
        done(error, null);
    }
}));

// Google Auth Route
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// Google Auth Callback
router.get("/google/callback", passport.authenticate("google", { session: false }), (req, res) => {
    const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.redirect(`${process.env.CLIENT_URL}/dashboard?token=${token}`);
});

// Get Logged-in User
router.get("/me", async (req, res) => {
    const token = req.header("Authorization").replace("Bearer ", "");
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId).select("-__v");
        res.json(user);
    } catch (error) {
        res.status(401).json({ error: "Invalid Token" });
    }
});

module.exports = router;
