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

// VERIFY OTP AND RESEND OTP CONTROLLER FUNCTIONS
export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Find user by email
    const user = await User.findOne({
      where: { email },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found.",
      });
    }

    // Check if account is already verified
    if (user.isVerified) {
      return res.status(400).json({
        message: "Account is already verified.",
      });
    }

    // Check OTP
    if (user.otp !== otp) {
      return res.status(400).json({
        message: "Invalid OTP.",
      });
    }

    // Check OTP expiry
    if (new Date() > user.otpExpiry) {
      return res.status(400).json({
        message: "OTP has expired. Please request a new one.",
      });
    }

    // Verify account
    user.isVerified = true;
    user.otp = null;
    user.otpExpiry = null;

    await user.save();

    return res.status(200).json({
      message: "Account verified successfully. You can now log in.",
    });
  } catch (error) {
    return res.status(500).json({
      message: "Something went wrong.",
      error: error.message,
    });
  }
};

// RESEND OTP CONTROLLER FUNCTION
export const resendOtp = async (req, res) => {
  try {
    const { email } = req.body;

    // Find user
    const user = await User.findOne({
      where: { email },
    });

    if (!user) {
      return res.status(404).json({
        message: "User not found.",
      });
    }

    // Check if account is already verified
    if (user.isVerified) {
      return res.status(400).json({
        message: "Account is already verified.",
      });
    }

    // Generate new OTP
    const otp = generateOtp();

    user.otp = otp;
    user.otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

    await user.save();

    // Send OTP email
    await sendMail({
      to: email,
      subject: "Your New OTP",
      html: `
        <h2>Assalam O Alaikum,</h2>
        <p>Your new OTP is:</p>
        <h3>${otp}</h3>
        <p>This OTP will expire in <b>10 minutes</b>.</p>
      `,
    });

    return res.status(200).json({
      message: "A new OTP has been sent to your email.",
    });
  } catch (error) {
    return res.status(500).json({
      message: "Something went wrong.",
      error: error.message,
    });
  }
};

// LOGIN CONTROLLER FUNCTION
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({
      where: { email },
    });

    // Check if user exists
    if (!user || !user.password) {
      return res.status(400).json({
        message: "Invalid email or password.",
      });
    }

    // Check if account is verified
    if (!user.isVerified) {
      return res.status(403).json({
        message: "Please verify your account using the OTP before logging in.",
      });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({
        message: "Invalid email or password.",
      });
    }

    // Generate JWT Token
    const token = generateToken({
      id: user.id,
      email: user.email,
    });

    // Success Response
    return res.status(200).json({
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    return res.status(500).json({
      message: "Something went wrong.",
      error: error.message,
    });
  }
};

// GOOGLE LOGIN CONTROLLER FUNCTION
export const googleLogin = async (req, res) => {
  try {
    const { idToken } = req.body;

    // Verify Google ID token
    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    // Get user information from Google
    const payload = ticket.getPayload();

    const { email, name, sub: googleId } = payload;

    // Find user by email
    let user = await User.findOne({
      where: { email },
    });

    // Create a new user if not found
    if (!user) {
      user = await User.create({
        name,
        email,
        googleId,
        isVerified: true,
      });
    }

    // Link Google account with existing user
    else if (!user.googleId) {
      user.googleId = googleId;

      await user.save();
    }

    // Generate JWT token
    const token = generateToken({
      id: user.id,
      email: user.email,
    });

    // Send response
    return res.status(200).json({
      message: "Google login successful.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    return res.status(500).json({
      message: "Something went wrong during Google login.",
      error: error.message,
    });
  }
};

// FORGOT PASSWORD  CONTROLLER FUNCTIONS

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res
        .status(404)
        .json({ message: "Is email se koi account nahi mila" });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");
    user.resetToken = resetToken;
    user.resetTokenExpiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minute valid
    await user.save();

    const resetLink = `${process.env.CLIENT_URL}/reset-password?token=${resetToken}&email=${email}`;

    await sendMail({
      to: email,
      subject: "Password Reset Request",
      html: `<p>Password reset karne ke liye is link par click karein:</p><a href="${resetLink}">${resetLink}</a><p>Ye link 15 minute mein expire ho jayegi.</p>`,
    });

    res.json({
      message: "Password reset link aapki email par bhej di gayi hai",
    });
  } catch (error) {
    res.status(500).json({ message: "Error", error: error.message });
  }
};

// RESET PASSWORD CONTROLLER FUNCTION
export const resetPassword = async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;
    const user = await User.findOne({ where: { email } });

    if (!user || user.resetToken !== token) {
      return res.status(400).json({ message: "Token invalid hai" });
    }
    if (new Date() > user.resetTokenExpiry) {
      return res.status(400).json({ message: "Token expire ho chuka hai" });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();

    res.json({
      message: "Password successfully change ho gaya, ab login karein",
    });
  } catch (error) {
    res.status(500).json({ message: "Error", error: error.message });
  }
};

// GET USER PROFILE CONTROLLER FUNCTION
export const getProfile = async (req, res) => {
  const user = await User.findByPk(req.user.id, {
    attributes: { exclude: ["password", "otp", "resetToken"] },
  });
  res.json({ user });
};
