const express = require("express");
const http = require("http");
const cors = require("cors");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
require("dotenv").config();

// Routes
const authRoutes = require("./routes/authRoutes.js");

const app = express();
const PORT = process.env.PORT || 5000;

// ===== Middleware =====
app.use(cors({
  origin: "https://jazzy-dusk-cd8f6f.netlify.app",
  credentials: true
}));
app.use(express.json());
app.use(cookieParser()); // ✅ Correct place

// ===== Routes =====
app.use("/api/auth", authRoutes); 

// ===== MongoDB Connection =====
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log("✅ MongoDB Connected"))
.catch(err => {
  console.error("❌ MongoDB connection failed:", err.message);
  process.exit(1);
});

// ===== Create HTTP Server =====
const server = http.createServer(app);

// ===== Start Server =====
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
