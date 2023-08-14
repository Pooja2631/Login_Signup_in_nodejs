const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://localhost/loginSignupDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useCreateIndex: true
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Error connecting to MongoDB:', err));

// User schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);
        
app.use(express.json());

// Signup route
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if the user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Error in signup:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Compare the password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid password' });
    }

    // Generate a JSON Web Token (JWT)
    const token = jwt.sign({ userId: user._id }, 'secret_key');

    res.status(200).json({ token });
  } catch (error) {
    console.error('Error in login:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Protected route
app.get('/protected', (req, res) => {
  res.send('You are authorized to access this protected route');
});

// Start the server
app.listen(3000, () => {
  console.log('Server started on port 3000');
});
