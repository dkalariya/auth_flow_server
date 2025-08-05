const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../model/User");

// Generate tokens
const generateAccessToken = (userId) => 
  jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: "7d" });

const generateRefreshToken = (userId) => 
  jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: "30d" });

// Register
exports.register = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Validate input
    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ name, email, password: hashedPassword });

    const accessToken = generateAccessToken(newUser._id);
    const refreshToken = generateRefreshToken(newUser._id);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", 
      sameSite: "Strict",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });

    res.status(201).json({ 
      token: accessToken, 
      user: { id: newUser._id, name: newUser.name, email: newUser.email }
    });

  } catch (err) {
    console.error("Register Error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

// Login
exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: "Invalid password" });

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "None",
      maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.json({
      token: accessToken,
      user: { id: user._id, name: user.name, email: user.email },
    });

  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ error: "Server error" });
  }
};

// Refresh token
exports.refreshToken = (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ error: "Refresh token missing" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    console.log("decoded",decoded);
    const newAccessToken = generateAccessToken(decoded.id);
    res.json({ token: newAccessToken });
  } catch (err) {
    console.error("Refresh Error:", err);
    res.status(403).json({ error: "Invalid or expired refresh token" });
  }
};
