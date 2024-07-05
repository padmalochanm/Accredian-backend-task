import express from "express";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import cors from "cors";

const app = express();
dotenv.config();
const PORT = process.env.PORT || 5000;
export const prisma = new PrismaClient();
const saltRounds = 10;
const email = process.env.EMAIL;
const password = process.env.PASSWORD;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: email, // Replace with your Gmail email
    pass: password, // Replace with your Gmail password or App-specific password
  },
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.userId = user.userId;
    next();
  });
};

app.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Check if username or email already exists
    const existingUser = await prisma.user.findFirst({
      where: {
        OR: [{ username: username }, { email: email }],
      },
    });

    if (existingUser) {
      let message = "Username or email already in use";
      if (existingUser.username === username) {
        message = "Username already exists";
      } else if (existingUser.email === email) {
        message = "Email address already exists";
      }
      return res.status(409).json({ message });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user using Prisma Client
    const newUser = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
      },
    });

    const payload = { userId: newUser.id };
    const secret = process.env.JWT_SECRET || "your_jwt_secret";
    const token = jwt.sign(payload, secret, { expiresIn: "1hr" });
    res.status(201).json({ message: "User registered successfully", token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Find user by username
    const user = await prisma.user.findUnique({
      where: {
        username: username,
      },
    });

    if (!user) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Compare hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Generate JWT token
    const payload = { userId: user.id };
    const secret = process.env.JWT_SECRET || "your_jwt_secret";
    const token = jwt.sign(payload, secret, { expiresIn: "1hr" });

    res.status(200).json({
      message: "Login successful",
      token,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.post("/referral", authenticateToken, async (req, res) => {
  try {
    const { refereeName, refereeEmail, message } = req.body;
    const referrerId = req.userId; // userId from authenticated token
    if (!refereeName || !refereeEmail) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const newReferral = await prisma.referral.create({
      data: {
        referrerId,
        refereeName,
        refereeEmail,
        message,
      },
    });

    const mailOptions = {
      from: "your-email@gmail.com",
      to: refereeEmail,
      subject: "You have been referred!",
      text: `Hello ${refereeName},\n\nYou have been referred by someone at Accredian.\n\nMessage: ${message}`,
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({
      message: "Referral created successfully",
      referral: newReferral,
    });
  } catch (error) {
    console.error("Error creating referral:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running successfully on port ${PORT}`);
});
