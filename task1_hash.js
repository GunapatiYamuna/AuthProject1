const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");

const app = express();
app.use(bodyParser.json());

// In-memory storage for users (no database required)
const users = [];

// Register API
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  // Check if user already exists
  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Store in memory
  users.push({ username, password: hashedPassword });

  res.json({ message: "User registered successfully" });
});

// Login API
app.post("/login",
