import bcrypt from "bcryptjs";
import crypto from "crypto";
import { OAuth2Client } from "google-auth-library";

import User from "../models/User.js";
import generateOtp from "../utils/otp.js";
import sendMail from "../utils/mailer.js";
import { generateToken } from "../utils/jwt.js";

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "All fields are required.",
      });
    }

    const existingUser = await User.findOne({
      where: { email },
    });

    if (existingUser) {
      return res.status(400).json({
        message: "Email is already registered.",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate OTP
    const otp = generateOtp();

    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    // Create user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      otp,
      otpExpiry,
      isVerified: false,
    });

    // Send verification email
    await sendMail({
      to: email,
      subject: "Verify Your Account",
      html: `
        <h2>Assalam O Alaikum ${name},</h2>
        <p>Your OTP for account verification is:</p>
        <h3>${otp}</h3>
        <p>This OTP will expire in <b>10 minutes</b>.</p>
      `,
    });

    return res.status(201).json({
      message:
        "Registration successful. Please verify your email using the OTP sent to your inbox.",
      userId: user.id,
    });
  } catch (error) {
    return res.status(500).json({
      message: "Something went wrong during registration.",
      error: error.message,
    });
  }
};
