

// routes/auth.routes.ts
import { Router } from "express";
import {
  register,
  registerFieldOfficer,
  login,
  googleAuth,
  addPhoneNumber,
  verifyEmail,
  resendVerification,
  forgotPassword,
  resetPassword,
  refreshAccessToken,
  logout,
  logoutAll,
  getMe,
  updateMe,
  changePassword,
  setPassword,
  approveUser,
  suspendUser,
  reactivateUser,
  completeProfile,
} from "@/controllers/auth";
import { authenticateToken, authorize } from "@/lib/auth";
import { UserRole } from "@prisma/client";
import rateLimit from "express-rate-limit";

const router = Router();

// ==================== RATE LIMITERS ====================

// Login rate limiter (5 attempts per 15 minutes)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: {
    success: false,
    error: "Too many login attempts. Please try again after 15 minutes.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Register rate limiter (10 attempts per hour)
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: {
    success: false,
    error: "Too many registration attempts. Please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Password reset rate limiter (3 attempts per 15 minutes)
const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3,
  message: {
    success: false,
    error: "Too many password reset attempts. Please try again later.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ==================== PUBLIC ROUTES ====================

// Registration
router.post("/register", registerLimiter, register);
router.post("/register/field-officer", registerLimiter, registerFieldOfficer);

// Login
router.post("/login", loginLimiter, login);

// Google OAuth
router.post("/google", googleAuth);

// Email Verification
router.post("/verify-email", verifyEmail);
router.post("/resend-verification", resendVerification);

// Password Reset
router.post("/forgot-password", passwordResetLimiter, forgotPassword);
router.post("/reset-password", resetPassword);

// Token Management
router.post("/refresh", refreshAccessToken);

// Logout (can work with or without auth)
router.post("/logout", logout);

// ==================== PROTECTED ROUTES ====================

// Apply authentication to all routes below
router.use(authenticateToken);

// User Profile
router.get("/me", getMe);
router.patch("/me", updateMe);

// Password Management
router.post("/change-password", changePassword);
router.post("/set-password", setPassword); // For OAuth users

// Add phone (for Google OAuth users)
router.post("/add-phone", addPhoneNumber);

// Logout from all devices
router.post("/logout-all", logoutAll);

// ==================== ADMIN ONLY ROUTES ====================

// User Management (Admin, Manager, Super Admin)
router.post(
  "/approve/:userId",
  authorize(UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.MANAGER),
  approveUser
);

router.post(
  "/suspend/:userId",
  authorize(UserRole.SUPER_ADMIN, UserRole.ADMIN),
  suspendUser
);
router.patch("/complete-profile", completeProfile);  // ← ADD THIS

router.post(
  "/reactivate/:userId",
  authorize(UserRole.SUPER_ADMIN, UserRole.ADMIN),
  reactivateUser
);

export default router;