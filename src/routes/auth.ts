// routes/auth.routes.ts
import { Router } from "express";
import {
  register,
  registerFieldOfficer,
  login,
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
  approveUser,
  suspendUser,
  reactivateUser,
} from "@/controllers/auth";
// import { authenticate, authorize } from "@/middleware/auth";
import { UserRole } from "@prisma/client";
import { authenticateToken, authorize } from "@/lib/auth";

const router = Router();

// ==================== PUBLIC ROUTES ====================

// Registration
router.post("/register", register);
router.post("/register/field-officer", registerFieldOfficer);

// Login
router.post("/login", login);

// Email Verification
router.post("/verify-email", verifyEmail);
router.post("/resend-verification", resendVerification);

// Password Reset
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);

// Token Management
router.post("/refresh", refreshAccessToken);

// ==================== PROTECTED ROUTES ====================

// Logout (can work with or without auth)
router.post("/logout", logout);

// These require authentication
router.use(authenticateToken);

// User Profile
router.get("/me", getMe);
router.patch("/me", updateMe);
router.post("/change-password", changePassword);

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

router.post(
  "/reactivate/:userId",
  authorize(UserRole.SUPER_ADMIN, UserRole.ADMIN),
  reactivateUser
);

export default router;