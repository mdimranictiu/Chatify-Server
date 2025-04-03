const express = require('express');
require('dotenv').config();
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5000;
const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nu3ic.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const bcrypt = require('bcrypt');
app.use(cors());
app.use(express.json());

// Generate Hash Password
const hashPassword = async (password) => {
  try {
    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);

    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
  } catch (error) {
    console.log("Error hashing Password", error);
  }
}

// Verify hashed password
const verifyPassword = async (enteredPassword, storedPassword) => {
  const isMatch = await bcrypt.compare(enteredPassword, storedPassword);
  if (isMatch) {
    return true;
  } else {
    return false;
  }
}

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {

    const Database = client.db(`${process.env.DB_USER}`);

    // collections
    const usersCollection = Database.collection('users');

    app.get('/', (req, res) => {
      res.send("Server running");
    });

    // Get single user for login 
    app.post('/api/auth/user', async (req, res) => {
      const data = req.body;
      const { email, password } = data;
      const user = await usersCollection.findOne({ email: email });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      // Use bcrypt to verify the password
      const isPasswordCorrect = await verifyPassword(password, user.password);
      if (!isPasswordCorrect) {
        return res.status(401).json({ message: "Incorrect Password" });
      }
      res.json(user);
    });

    // Register new user
    app.post('/api/auth/register/user', async (req, res) => {
      const data = req.body;
      const { name, email, password } = data;

      // Check if the user already exists
      const existingUser = await usersCollection.findOne({ email: email });
      if (existingUser) {
        return res.status(400).json({ message: "User with this email already exists" });
      }

      // If the user doesn't exist, hash the password and register the user
      const securePassword = await hashPassword(password);
      const userInfo = {
        name,
        email,
        password: securePassword,
        profilePicture: '', // You can add logic to upload a profile picture if necessary
        status: '',
        bio: '',
        blockedUsers: [],
        isOnline: false,
        createdAt: new Date().toISOString(),
        role: 'user',
      };

      const response = await usersCollection.insertOne(userInfo);
      res.status(201).json({ message: "User registered successfully", userId: response.insertedId });
    });

    // Get all users (for testing)
    app.get('/users', async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    console.log("You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(`Server is running: http://localhost:${port}`);
});
