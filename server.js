const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const validator = require('validator');

const app = express();
const PORT = 3000;
const saltRounds = 10; // Number of salt rounds for bcrypt
const maxLoginAttempts = 5; // Max failed login attempts before lockout

// Middleware to parse JSON data from incoming requests
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Initialize session middleware
app.use(
  session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Use 'true' if HTTPS is enabled
  })
);

// Serve static files (your HTML files)
app.use(express.static(path.join(__dirname)));

// File path to store user data
const dataFilePath = path.join(__dirname, 'users.json');

// Utility function to read user data from the JSON file
function readUserData() {
  if (fs.existsSync(dataFilePath)) {
    const data = fs.readFileSync(dataFilePath);
    return JSON.parse(data);
  }
  return [];
}

// Utility function to write user data to the JSON file
function writeUserData(data) {
  fs.writeFileSync(dataFilePath, JSON.stringify(data, null, 2));
}

// Handle registration
app.post('/register', async (req, res) => {
  const { username, password, email, name, mobile } = req.body;

  if (!username || !password || !email || !name || !mobile) {
    return res.send("<script>alert('All fields are required.'); window.location.href = '/register.html';</script>");
  }

  if (!validator.isEmail(email)) {
    return res.send("<script>alert('Invalid email format.'); window.location.href = '/register.html';</script>");
  }

  if (!validator.isMobilePhone(mobile, 'any')) {
    return res.send("<script>alert('Invalid mobile number.'); window.location.href = '/register.html';</script>");
  }

  const sanitizedUsername = validator.escape(username);
  const sanitizedEmail = validator.escape(email);
  const sanitizedName = validator.escape(name);
  const sanitizedMobile = validator.escape(mobile);

  const users = readUserData();

  // Check if user already exists
  if (users.find((user) => user.username === sanitizedUsername)) {
    return res.send("<script>alert('User already exists.'); window.location.href = '/register.html';</script>");
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  // Add new user with hashed password
  users.push({
    username: sanitizedUsername,
    password: hashedPassword,
    email: sanitizedEmail,
    name: sanitizedName,
    mobile: sanitizedMobile,
    failedAttempts: 0,
    isLocked: false,
  });
  writeUserData(users);

  res.send("<script>alert('Registration successful! You can now log in.'); window.location.href = '/login.html';</script>");
});

// Handle login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.send("<script>alert('Username and password are required.'); window.location.href = '/login.html';</script>");
  }

  const users = readUserData();
  const user = users.find((user) => user.username === username);

  if (!user) {
    return res.send("<script>alert('Invalid credentials.'); window.location.href = '/login.html';</script>");
  }

  if (user.isLocked) {
    return res.send("<script>alert('Account is locked due to multiple failed login attempts.'); window.location.href = '/login.html';</script>");
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    user.failedAttempts += 1;
    if (user.failedAttempts >= maxLoginAttempts) {
      user.isLocked = true;
    }
    writeUserData(users);
    return res.send("<script>alert('Invalid credentials.'); window.location.href = '/login.html';</script>");
  }

  // Reset failed attempts on successful login
  user.failedAttempts = 0;
  writeUserData(users);

  // Create a session
  req.session.user = user;
  res.send("<script>alert('Login successful!'); window.location.href = '/home.html';</script>");
});

// Forgot Password
app.post('/forgot-password', (req, res) => {
  const { username, email, mobile } = req.body;

  if (!username || (!email && !mobile)) {
    return res.send("<script>alert('Please provide username and either email or mobile number.'); window.location.href = '/forgot-password.html';</script>");
  }

  const users = readUserData();
  const user = users.find((user) => user.username === username);

  if (!user) {
    return res.send("<script>alert('User not found.'); window.location.href = '/forgot-password.html';</script>");
  }

  if (user.email !== email && user.mobile !== mobile) {
    return res.send("<script>alert('Provided information does not match our records.'); window.location.href = '/forgot-password.html';</script>");
  }

  // Here, you would normally generate a reset token and send an email/SMS. For simplicity:
  res.send("<script>alert('Verification successful. You can now reset your password.'); window.location.href = '/reset-password.html';</script>");
});

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  }
  res.status(401).send('Please login to access this page.');
}

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("<script>alert('Error logging out.'); window.location.href = '/home.html';</script>");
    }
    res.send("<script>alert('Logged out successfully.'); window.location.href = '/login.html';</script>");
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
