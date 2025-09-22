const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(bodyParser.json());

// In-memory storage (no DB required)
const users = [];

// Secret key for JWT
const JWT_SECRET = "mySecretKey";

// --------------------
// Register (Password Hashing)
// --------------------
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

  // Hash password before saving
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });

  res.json({ message: "User registered successfully" });
});

// --------------------
// Login (Password Verify + JWT Issue)
// --------------------
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Generate JWT
  const token = jwt.sign({ username: user.username }, JWT_SECRET, {
    expiresIn: "1h",
  });

  res.json({ message: "Login successful", token });
});

// --------------------
// Protected Profile Route (JWT Required)
// --------------------
app.get("/profile", (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ message: "Unauthorized, no token provided" });
  }

  const token = authHeader.split(" ")[1]; // Format: "Bearer <token>"

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Unauthorized or expired token" });
    }

    res.json({ message: `Welcome ${decoded.username}` });
  });
});

// --------------------
// Start server
// --------------------
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
