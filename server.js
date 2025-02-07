const express = require("express");
const app = express();
const port = process.env.PORT || 3000;
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const Ajv = require("ajv");
const ajvFormats = require("ajv-formats");

app.use(express.json());

// ------ WRITE YOUR SOLUTION HERE BELOW ------//

// Configure AJV validation \\ 
const ajv = new Ajv({ allErrors: true });
ajvFormats(ajv);

// In-memory storage for users and scores \\
const users = [];
const scores = [];

// Schemas \\
const userSchema = {
  type: "object",
  properties: {
    userHandle: { type: "string", minLength: 6 },
    password: { type: "string", minLength: 6 },
  },
  required: ["userHandle", "password"],
  additionalProperties: false,
};

const scoreSchema = {
  type: "object",
  properties: {
    level: { type: "string" },
    userHandle: { type: "string" },
    score: { type: "integer" },
    timestamp: { type: "string", format: "date-time" },
  },
  required: ["level", "userHandle", "score", "timestamp"],
  additionalProperties: false,
};

// Validation middleware \\ 
function validateBody(schema) {
  return (req, res, next) => {
    const validate = ajv.compile(schema);
    if (!validate(req.body)) {
      return res.status(400).json({ errors: validate.errors });
    }
    next();
  };
}

// Authentication middleware \\ 
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET || "your_jwt_secret_key", (err, user) => {
    if (err) return res.sendStatus(401);
    req.user = user;
    next();
  });
}

// ------ Endpoints Implementation ------ //

// Signup endpoint
app.post("/signup", validateBody(userSchema), async (req, res) => {
  const { userHandle, password } = req.body;

  // Check if user already exists \\
  const existingUser = users.find(u => u.userHandle === userHandle);
  if (existingUser) {
    // If the same credentials are provided, consider it idempotent \\ 
    if (await bcrypt.compare(password, existingUser.password)) {
      return res.sendStatus(201);
    } else {
      return res.status(400).json({ message: "User already exists" });
    }
  }

  // Hash password and store user \\ 
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ userHandle, password: hashedPassword });
  res.sendStatus(201);
});

// Login endpoint \\ 
app.post("/login", validateBody(userSchema), async (req, res) => {
  const { userHandle, password } = req.body;
  console.log(" Checking login for:", userHandle); 

  const user = users.find(u => u.userHandle === userHandle);
  console.log(" Found user:", user ? "Yes" : "No"); 
  if (!user || !(await bcrypt.compare(password, user.password))) {
    console.log("Login failed");
    return res.sendStatus(401);
  }

  console.log("Login successful");
  const token = jwt.sign({ userHandle }, process.env.JWT_SECRET || "your_jwt_secret_key", { expiresIn: "1h" });
  res.json({ jsonWebToken: token });
});
// Submit high score endpoint \\ 
app.post("/high-scores", authenticateToken, validateBody(scoreSchema), (req, res) => {
  scores.push(req.body);
  scores.sort((a, b) => b.score - a.score);
  res.sendStatus(201);
});

// Get high scores endpoint \\ 
app.get("/high-scores", (req, res) => {
  const { level, page = 1 } = req.query;
  if (!level) return res.status(400).json({ message: "Level is required" });

  const filteredScores = scores
    .filter(s => s.level === level)
    .sort((a, b) => b.score - a.score);

  const pageSize = 20;
  const startIndex = (page - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const paginatedScores = filteredScores.slice(startIndex, endIndex);

  res.json(paginatedScores);
});

//------ WRITE YOUR SOLUTION ABOVE THIS LINE ------//
let serverInstance = null;
module.exports = {
  start: function () {
    serverInstance = app.listen(port, () => {
      console.log(`Server running at http://localhost:${port}`);
    });
  },
  close: function () {
    serverInstance.close();
  },
};