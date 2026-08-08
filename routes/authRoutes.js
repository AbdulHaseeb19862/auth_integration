import express from "express";

import * as authController from "../controllers/authController.js";
import protect from "../middleware/authMiddleware.js";

const router = express.Router();

// Authentication routes
router.post("/register", authController.register);
router.post("/verify-otp", authController.verifyOtp);
router.post("/resend-otp", authController.resendOtp);
router.post("/login", authController.login);
router.post("/google-login", authController.googleLogin);

// Password routes
router.post("/forgot-password", authController.forgotPassword);

router.post("/reset-password", authController.resetPassword);

// Protected route
router.get("/profile", protect, authController.getProfile);

export default router;
