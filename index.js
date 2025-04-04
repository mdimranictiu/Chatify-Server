const express = require('express');
require('dotenv').config();
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 5000;
const { MongoClient, ServerApiVersion } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nu3ic.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const bcrypt = require('bcrypt');
const nodemailer = require("nodemailer");

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
// generate otp
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
  }
});
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

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

    //reset password logic
    app.post('/auth/reset-password', async(req,res)=>{
      const email= req.body.email;
     // first check if the email exists in db
     const existingUser = await usersCollection.findOne({ email: email });
     if (!existingUser) {
       return res.status(404).json({ message: "User Not Found" });
     }
     else{
      const otp = generateOTP();
      const otpExpires = new Date(Date.now() + 5 * 60000); // Expire in 5 minutes
      console.log(otp)
      await usersCollection.updateOne({ email }, { $set: { otp, otpExpires } });
     
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Password Reset Verification Code",
        text: `Dear User,  
    
    We received a request to reset your password. Please use the following One-Time Password (OTP) to proceed:  
    
    **${otp}**  
    
    This OTP will expire in 5 minutes. If you did not request this, please ignore this email.  
    
    Best regards,  
    Chatify Support Team`
    };
    
    transporter.sendMail(mailOptions, (err, info) => {
      if (err) return res.status(500).json({ message: "Email sending failed" });
      res.json({message: "An OTP has been sent to your email. Please check your inbox or spam folder. The OTP will expire in 5 minutes"});
  });
     }
      
    })

    app.post('/reset-password/verify-otp', async(req,res)=>{
      const data= req.body;
      const {email,otp}=data;
      const user= await usersCollection.findOne({email:email})
      
      if(!user || user.otp !==otp || new Date()> new Date(user.otpExpires)){
        return res.status(400).json({message: "Invalid or Expired OTP"})
      }
      await usersCollection.updateOne({email},{$unset :{otp: "",otpExpires:""}})
      res.json({message: "Your OTP has been successfully verified"})

    })
  
    app.post('/auth/password/reset',async(req,res)=>{
      const data= req.body;
      const {email,password}=data;
      try {
        const securePassword= await hashPassword(password);
      await usersCollection.updateOne({ email }, { $set: {password: securePassword} });
      res.json({ message: "Password reset successful" });
      } catch (error) {
        res.json({message: "Something went Wrong"})
      }
    })
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
