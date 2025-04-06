const express = require('express');
require('dotenv').config();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require("nodemailer");
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;
const { MongoClient, ServerApiVersion } = require('mongodb');

const app = express();
const port = process.env.PORT || 5000;

// MongoDB connection URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nu3ic.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Cloudinary config
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Middlewares
app.use(cors());
app.use(express.json());

// Multer + Cloudinary config
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: 'user_profiles',
    allowed_formats: ['jpg', 'jpeg', 'png'],
    transformation: [{ width: 300, height: 300, crop: 'limit' }],
  },
});
const upload = multer({ storage });

// Password hashing function
const hashPassword = async (password) => {
  const saltRounds = 10;
  const salt = await bcrypt.genSalt(saltRounds);
  return await bcrypt.hash(password, salt);
};

// Verify password
const verifyPassword = async (enteredPassword, storedPassword) => {
  return await bcrypt.compare(enteredPassword, storedPassword);
};

// Nodemailer transport
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// OTP generator
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// MongoDB client setup
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
    const usersCollection = Database.collection('users');

    app.get('/', (req, res) => {
      res.send("Server running");
    });

    // Login
    app.post('/api/auth/user', async (req, res) => {
      const { email, password } = req.body;
      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(404).json({ message: "User not found" });

      const isPasswordCorrect = await verifyPassword(password, user.password);
      if (!isPasswordCorrect) return res.status(401).json({ message: "Incorrect Password" });

      res.json(user);
    });

    // Register
    app.post('/api/auth/register/user', async (req, res) => {
      const { name, email, password } = req.body;
      const existingUser = await usersCollection.findOne({ email });
      if (existingUser) return res.status(400).json({ message: "User with this email already exists" });

      const securePassword = await hashPassword(password);
      const userInfo = {
        name,
        email,
        password: securePassword,
        profilePicture: '',
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

    // Forgot Password - Send OTP
    app.post('/auth/reset-password', async (req, res) => {
      const { email } = req.body;
      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(404).json({ message: "User Not Found" });

      const otp = generateOTP();
      const otpExpires = new Date(Date.now() + 5 * 60000); // 5 minutes

      await usersCollection.updateOne({ email }, { $set: { otp, otpExpires } });

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Password Reset Verification Code",
        text: `
Dear User,

We received a request to reset your password. Use the OTP below:

${otp}

This OTP will expire in 5 minutes.

Best regards,
Chatify Support Team`
      };

      transporter.sendMail(mailOptions, (err, info) => {
        if (err) return res.status(500).json({ message: "Email sending failed" });
        res.json({ message: "OTP sent to email. Please check inbox/spam." });
      });
    });

    // Verify OTP
    app.post('/reset-password/verify-otp', async (req, res) => {
      const { email, otp } = req.body;
      const user = await usersCollection.findOne({ email });

      if (!user || user.otp !== otp || new Date() > new Date(user.otpExpires)) {
        return res.status(400).json({ message: "Invalid or Expired OTP" });
      }

      await usersCollection.updateOne({ email }, { $unset: { otp: "", otpExpires: "" } });
      res.json({ message: "OTP verified successfully" });
    });

    // Set New Password
    app.post('/auth/password/reset', async (req, res) => {
      const { email, password } = req.body;
      try {
        const securePassword = await hashPassword(password);
        await usersCollection.updateOne({ email }, { $set: { password: securePassword } });
        res.json({ message: "Password reset successful" });
      } catch (error) {
        res.status(500).json({ message: "Something went wrong" });
      }
    });

    // Get All Users (test route)
    app.get('/users', async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });

    // Find user by email
    app.post('/auth/find/Profile', async (req, res) => {
      const { email } = req.body;
      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(404).json({ message: "User Not Found" });

      const { password, ...rest } = user;
      res.send(rest);
    });

    // Update user profile (with image)
    app.patch("/auth/update/profile", upload.single("image"), async (req, res) => {
      try {
        const { name, bio, email } = req.body;
        console.log("Request received with:", { name, bio, email });
    
        const imageUrl = req.file?.path;
        console.log("Image URL:", imageUrl);
    
        const updateData = { name, bio };
        if (imageUrl) updateData.profilePicture = imageUrl;
    
        const updatedUser = await usersCollection.findOneAndUpdate(
          { email },
          { $set: updateData },
          { returnDocument: "after", projection: { password: 0 } }
        );
    
        if (!updatedUser.value) {
          return res.status(404).json({ message: "User not found" });
        }
    
        res.status(200).json(updatedUser.value);
      } catch (err) {
        console.error("Profile update error:", err);
        res.status(500).json({ message: "Failed to update profile" });
      }
    });
    // update settings
    app.patch('/api/update-settings', async (req, res) => {
    
      const { email, field, value } = req.body;
    
      try {
        const user = await usersCollection.findOne({ email: email });
    
        if (!user) {
          return res.status(404).json({ message: "User not Found" });
        }
    
        const updateObj = {};
        updateObj[field] = value;

    
        const result = await usersCollection.updateOne(
          { email: email },
          { $set: updateObj }
        );
    
        if (result.modifiedCount > 0) {
          return res.json({ message: "Setting updated successfully" });
        } else {
          return res.status(400).json({ message: "No changes made" });
        }
    
      } catch (error) {
        console.error("Update error:", error);
        res.status(500).json({ message: "Internal Server Error" });
      }
    });
    
    

    console.log(" MongoDB Connected Successfully");
  } finally {
    // Optional: keep client open if long running app
  }
}

run().catch(console.dir);

app.listen(port, () => {
  console.log(` Server is running: http://localhost:${port}`);
});
