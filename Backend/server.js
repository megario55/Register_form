// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect('mongodb+srv://demonewuser17:demonewuser@cluster0.g87w9nq.mongodb.net/Registeruser?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
try {
  mongoose.connection.on('connected', () => {
    console.log('Connected to MongoDB');
  });
} catch (error) {
  console.error('Error connecting to MongoDB:', error.message);
}

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  college: String,
  whatsapp: String,
  phone: String,
  password: String,
  expireDate: Date,
});

const User = mongoose.model('User', userSchema);

const generateToken = (user) => {
  return jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
};

app.post('/api/register', async (req, res) => {
  const { name, email, college, whatsapp, phone, password, expiry } = req.body;
  const expiryMap = {
    '1day': 1,
    '1week': 7,
    '1month': 30,
    '3month': 90,
    "6month": 180,
    "1year": 365,
    "2year": 730,
    "3year": 1095,
    "4year": 1460,
  };
  const expireDate = new Date();
  expireDate.setDate(expireDate.getDate() + expiryMap[expiry]);

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name,
      email,
      college,
      whatsapp,
      phone,
      password: hashedPassword,
      expireDate
    });
    await user.save();
    res.status(201).json({ message: 'Registered Successfully' });
  } catch (error) {
    res.status(400).json({ error: 'Email already exists' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.status(404).json({ error: 'User not found' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const now = new Date();
  if (now > user.expireDate) {
    return res.status(403).json({ error: 'Plan expired' });
  }

  const token = generateToken(user);
  res.json({ token, user });
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.userId = user.id;
    next();
  });
};

app.get('/api/profile', authenticateToken, async (req, res) => {
  const user = await User.findById(req.userId).select('-password');
  res.json(user);
});

app.get('/api/users', authenticateToken, async (req, res) => {
  const users = await User.find().select('-password');
  res.json(users);
});

app.listen(5000, () => console.log('Server running on port 5000'));
