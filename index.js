const express = require("express");
require("dotenv").config();
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const http = require("http");
const { Server } = require("socket.io");
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

//create HTTP server
const server = http.createServer(app);

// socket.io init
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

// check Connection of socket io

// Multer + Cloudinary config
const storage = new CloudinaryStorage({
  cloudinary,
  params: {
    folder: "user_profiles",
    allowed_formats: ["jpg", "jpeg", "png"],
    transformation: [{ width: 300, height: 300, crop: "limit" }],
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
const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

// MongoDB client setup
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const Database = client.db(`${process.env.DB_USER}`);
    const usersCollection = Database.collection("users");
    const messagesCollection = Database.collection("messages");

    app.get("/", (req, res) => {
      res.send("Server running");
    });

    // Login system implementation
    app.post("/api/auth/user", async (req, res) => {
      const { email, password } = req.body;
      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(404).json({ message: "User not found" });

      const isPasswordCorrect = await verifyPassword(password, user.password);
      if (!isPasswordCorrect)
        return res.status(401).json({ message: "Incorrect Password" });
      await usersCollection.updateOne(
        { _id: user._id },
        { $set: { isOnline: true, logOutTime: "" } }
      );
      res.json(user);
    });

    // Implement JWT for token generate and send it to frontend
    app.post("/api/jwt", async (req, res) => {
      const { email } = req.body;
      const user = { email: email };
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1h",
      });
      res.send({ token });
    });

    // verifytoken each api request
    const verifyToken = (req, res, next) => {
      if (!req.headers.authorization) {
        return res.status(401).send("Forbidden Access");
      }
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send("Forbidden Access");
        }
        req.decoded = decoded;
        next();
      });
    };

    // Register a new user
    app.post("/api/auth/register/user", async (req, res) => {
      const { name, email, password } = req.body;
      const existingUser = await usersCollection.findOne({ email });
      if (existingUser)
        return res
          .status(400)
          .json({ message: "User with this email already exists" });

      const securePassword = await hashPassword(password);
      const userInfo = {
        name,
        email,
        password: securePassword,
        profilePicture: "",
        status: "public",
        bio: `I'm ${name}, and I'm here to make chatting more fun and friendly! Thanks Chatify for this amazing platform.`,
        blockedUsers: [],
        isOnline: false,
        createdAt: new Date().toISOString(),
        role: "user",
        profilePhotoVisibility: "everyone",
        isOnline: true,
      };

      const response = await usersCollection.insertOne(userInfo);
      res
        .status(201)
        .json({
          message: "User registered successfully",
          userId: response.insertedId,
        });
    });
    // Log Out from browser and here store logOut time also to catch active status
    app.post("/api/auth/logOut", async (req, res) => {
      const { email } = req.body;

      const user = await usersCollection.findOne({ email: email });
      if (!user) return res.status(404).json({ message: "User not found" });
      await usersCollection.updateOne(
        { email: user?.email },
        { $set: { isOnline: false, logOutTime: new Date() } }
      );
      res.send(user);
    });
    // Forgot Password - Send OTP
    app.post("/auth/reset-password", async (req, res) => {
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
Chatify Support Team`,
      };

      transporter.sendMail(mailOptions, (err, info) => {
        if (err)
          return res.status(500).json({ message: "Email sending failed" });
        res.json({ message: "OTP sent to email. Please check inbox/spam." });
      });
    });

    // Verify OTP for  reset password
    app.post("/reset-password/verify-otp", async (req, res) => {
      const { email, otp } = req.body;
      const user = await usersCollection.findOne({ email });

      if (!user || user.otp !== otp || new Date() > new Date(user.otpExpires)) {
        return res.status(400).json({ message: "Invalid or Expired OTP" });
      }

      await usersCollection.updateOne(
        { email },
        { $unset: { otp: "", otpExpires: "" } }
      );
      res.json({ message: "OTP verified successfully" });
    });

    // Set New Password
    app.post("/auth/password/reset", async (req, res) => {
      const { email, password } = req.body;
      try {
        const securePassword = await hashPassword(password);
        await usersCollection.updateOne(
          { email },
          { $set: { password: securePassword } }
        );
        res.json({ message: "Password reset successful" });
      } catch (error) {
        res.status(500).json({ message: "Something went wrong" });
      }
    });

    // Get All Users (test route)
    app.get("/users", verifyToken, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });
    // get all message (test route)
    app.get("/messages", verifyToken, async (req, res) => {
      const result = await messagesCollection.find().toArray();
      res.send(result);
    });

    // Find user by email
    app.post("/auth/find/Profile", verifyToken, async (req, res) => {
      const { email } = req.body;
      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(404).json({ message: "User Not Found" });

      const { password, ...rest } = user;
      res.send(rest);
    });

    // Update user profile (with image)
    app.patch(
      "/auth/update/profile",
      upload.single("image"),
      async (req, res) => {
        try {
          const { name, bio, email } = req.body;

          const imageUrl = req.file?.path;

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
          res.status(500).json({ message: "Failed to update profile" });
        }
      }
    );
    // update settings
    app.patch("/api/update-settings/", verifyToken, async (req, res) => {
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
        res.status(500).json({ message: "Internal Server Error" });
      }
    });

    //fetch all online users who are active right now
    app.post("/api/find/onlineUsers", verifyToken, async (req, res) => {
      const { email } = req.body;
      const query = {
        OnlineStatus: "true",
        isOnline: true,
        email: { $ne: email },
      };
      const otherOnlineUsers = await usersCollection.find(query).toArray();
      const result = otherOnlineUsers.map((user) => ({
        username: user.name,
        profilePicture: user.profilePicture,
        profilePhotoVisibility: user.profilePhotoVisibility,
        emailId: user.email,
        id: user._id,
      }));

      res.send(result);
    });

    //find  all contacts ( inactive + active)
    app.post("/api/find/all/contacts", verifyToken, async (req, res) => {
      const { email } = req.body;
      const search = req.query?.search;
      const query = {
        name: { $regex: search, $options: "i" },
      };
      try {
        const allContacts = await usersCollection.find(query).toArray();

        const othersContacts = allContacts.filter(
          (user) => user?.email !== email
        );

        const result = othersContacts.map((user) => ({
          name: user.name,
          profilePicture: user.profilePicture,
          email: user.email,
          id: user._id,
          isOnline: user.isOnline,
          profilePhotoVisibility: user.profilePhotoVisibility,
          staus: user.status,
          OnlineStatus: user.OnlineStatus,
        }));

        res.send(result);
      } catch (error) {
        res.status(500).json({
          message: "Failed to fetch recent contacts",
          error: error.message,
        });
      }
    });
    // For send Message find Reciver Information
    app.post("/auth/find/receiver/", verifyToken, async (req, res) => {
      const { _id } = req.body;
      const receiverId = _id;
      try {
        const user = await usersCollection.findOne({
          _id: new ObjectId(receiverId),
        });
        if (!user) return res.status(404).json({ message: "User Not Found" });

        const { password, ...rest } = user;
        res.send(rest);
      } catch (error) {
        console.log(error.message);
      }
    });

    // api to get messages btw sender and receiver
    app.post("/api/get/messages", verifyToken, async (req, res) => {
      const { senderId, receiverId } = req.body;
      try {
        const messages = await messagesCollection
          .find({
            $or: [
              { senderId: senderId, receiverId: receiverId },
              { senderId: receiverId, receiverId: senderId },
            ],
          })
          .sort({ timestamp: 1 })
          .toArray();
        res.send(messages);
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // api for send single Message (test route)
    app.post("/api/send/message", verifyToken, async (req, res) => {
      const { text, senderId, receiverId } = req.body;
      const timestamp = new Date().toISOString();
      try {
        const message = {
          text: text,
          senderId: senderId,
          receiverId: receiverId,
          timestamp: timestamp,
        };
        const result = await messagesCollection.insertOne(message);
        res.status(200).json({ result });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    let onlineUsers = {};

    io.on("connection", (socket) => {
      // console.log('A user connected');
      socket.on("join", (userId) => {
        onlineUsers[userId] = socket.id;
        socket.userId = userId;
        // console.log(`${userId} joined the chat`);
      });

      socket.on("disconnect", () => {
        if (socket.userId) {
          delete onlineUsers[socket.userId];
          //console.log(`${socket.userId} disconnected`);
        }
      });

      socket.on("send_message", async (messageData) => {
        const { text, senderId, receiverId } = messageData;
        const timestamp = new Date().toISOString();
        const message = {
          text: text,
          senderId: senderId,
          receiverId: receiverId,
          timestamp: timestamp,
        };
        try {
          const result = await messagesCollection.insertOne(message);
          const receiverSocketId = onlineUsers[receiverId];
          if (receiverSocketId) {
            io.to(receiverSocketId).emit("receiveMessage", message);
          }
        } catch (error) {
          console.log("Faild");
        }
      });
    });

    // find recent users
    app.post("/api/find/recent", verifyToken, async (req, res) => {
      const { userId } = req.body;
      const search = req.query?.search;
      const query = {
        name: { $regex: search, $options: "i" },
      };

      // first fetch all messages that I send by last time
      try {
        if (userId) {
          // find all messages receiver id
          const lastMessagesUsers = await messagesCollection
            .find(
              { senderId: userId },
              { projection: { receiverId: 1, _id: 0 } }
            )
            .sort({ timestamp: -1 })
            .toArray();
          // make the id uniques
          const uniqueReceiverIdSet = new Set();
          const uniqueReceiverIds = [];
          for (const msg of lastMessagesUsers) {
            if (!uniqueReceiverIdSet.has(msg.receiverId)) {
              uniqueReceiverIdSet.add(msg.receiverId);
              uniqueReceiverIds.push(msg.receiverId);
              //console.log(msg.receiverId)
            }
          }
          //console.log(uniqueReceiverIds)

          const fetchDataTime = new Date();
          const recentUserProfiles = await Promise.all(
            uniqueReceiverIds.map(async (receiverId) => {
              const profile = await usersCollection.findOne({
                _id: new ObjectId(receiverId),
              });
              if (profile) {
                const {
                  name,
                  profilePicture,
                  _id,
                  isOnline,
                  OnlineStatus,
                  profilePhotoVisibility,
                  logOutTime,
                } = profile;
                //console.log(profile)
                return {
                  name,
                  profilePicture,
                  _id,
                  isOnline,
                  OnlineStatus,
                  profilePhotoVisibility,
                  logOutTime,
                  fetchDataTime: fetchDataTime,
                };
              }
            })
          );
          const finalData = recentUserProfiles.filter((user) =>
            user?.name?.toLowerCase().includes(search?.toLowerCase())
          );
          res.send(finalData);
        }
      } catch (error) {
        console.log(error.message);
      }
    });

    console.log(" MongoDB Connected Successfully");
  } finally {
    // Optional: keep client open if long running app
  }
}

run().catch(console.dir);

server.listen(port, () => {
  console.log(` Server is running: http://localhost:${port}`);
});