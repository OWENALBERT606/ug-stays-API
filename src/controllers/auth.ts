// controllers/auth.ts
import { Request, Response } from "express";
import crypto from "crypto";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import { db } from "@/db/db";
import { sendResetEmailResend } from "@/utils/mailer";
import { sendVerificationCodeResend } from "@/lib/mailer";
import { UserRole, UserStatus } from "@prisma/client";

// ==================== CONFIG ====================
const ACCESS_TOKEN_TTL = "15m";
const REFRESH_TOKEN_DAYS = 30;
const REFRESH_TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * REFRESH_TOKEN_DAYS;
const RESET_TTL_MIN = 30;
const VERIFICATION_CODE_LENGTH = 6;

// ==================== HELPER FUNCTIONS ====================

function generateVerificationCode(): string {
  return String(crypto.randomInt(0, 1_000_000)).padStart(VERIFICATION_CODE_LENGTH, "0");
}

function generateTokens(user: { id: string; role: UserRole }) {
  const accessToken = jwt.sign(
    { sub: user.id, role: user.role },
    process.env.JWT_SECRET!,
    { expiresIn: ACCESS_TOKEN_TTL }
  );

  const refreshToken = crypto.randomUUID();

  return { accessToken, refreshToken };
}

function sanitizeUser(user: any) {
  return {
    id: user.id,
    userId: user.userId,
    email: user.email,
    phone: user.phone,
    role: user.role,
    status: user.status,
    firstName: user.firstName,
    lastName: user.lastName,
    name: user.name,
    imageUrl: user.imageUrl,
    emailVerified: user.emailVerified,
    createdAt: user.createdAt,
  };
}

// ==================== REGISTER ====================

/**
 * Register a new user (Tenant by default)
 * POST /auth/register
 */
export async function register(req: Request, res: Response) {
  try {
    const {
      firstName,
      lastName,
      email,
      phone,
      password,
      role = UserRole.TENANT, // Default to tenant
    } = req.body;

    // Validation
    if (!firstName || !lastName || !email || !phone || !password) {
      return res.status(400).json({
        success: false,
        error: "All fields are required: firstName, lastName, email, phone, password",
      });
    }

    // Normalize email and phone
    const normalizedEmail = email.trim().toLowerCase();
    const normalizedPhone = phone.trim().replace(/\s+/g, "");

    // Check if user already exists
    const existingUser = await db.user.findFirst({
      where: {
        OR: [{ email: normalizedEmail }, { phone: normalizedPhone }],
      },
    });

    if (existingUser) {
      const field = existingUser.email === normalizedEmail ? "email" : "phone";
      return res.status(409).json({
        success: false,
        error: `User with this ${field} already exists`,
      });
    }

    // Hash password
    const hashedPassword = await bcryptjs.hash(password, 12);

    // Generate verification code
    const verificationCode = generateVerificationCode();

    // Determine initial status based on role
    let initialStatus = UserStatus.PENDING;
    let requiresApproval = false;

    // Field officers and admins need approval
    const rolesRequiringApproval: UserRole[] = [UserRole.FIELD_OFFICER, UserRole.ADMIN, UserRole.MANAGER];
    if (rolesRequiringApproval.includes(role as UserRole)) {
      requiresApproval = true;
    }

    // Create user
    const user = await db.user.create({
      data: {
        firstName,
        lastName,
        name: `${firstName} ${lastName}`,
        email: normalizedEmail,
        phone: normalizedPhone,
        password: hashedPassword,
        role: role as UserRole,
        status: initialStatus,
        isApproved: !requiresApproval,
        token: verificationCode,
        emailVerified: false,
      },
    });

    // Send verification email
    await sendVerificationCodeResend({
      to: user.email,
      name: user.firstName,
      code: verificationCode,
    });

    // Log activity
    await db.activityLog.create({
      data: {
        userId: user.id,
        action: "USER_REGISTERED",
        module: "auth",
        entityType: "User",
        entityId: user.id,
        status: "SUCCESS",
        description: `New ${role} registered: ${user.email}`,
      },
    });

    return res.status(201).json({
      success: true,
      message: "Registration successful. Please check your email for verification code.",
      data: {
        userId: user.id,
        email: user.email,
        requiresApproval,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({
      success: false,
      error: "Registration failed. Please try again.",
    });
  }
}

/**
 * Register a new Field Officer (Admin only)
 * POST /auth/register/field-officer
 */
export async function registerFieldOfficer(req: Request, res: Response) {
  try {
    const {
      firstName,
      lastName,
      email,
      phone,
      password,
    } = req.body;

    // Validation
    if (!firstName || !lastName || !email || !phone || !password) {
      return res.status(400).json({
        success: false,
        error: "All fields are required",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const normalizedPhone = phone.trim().replace(/\s+/g, "");

    // Check existing
    const existingUser = await db.user.findFirst({
      where: {
        OR: [{ email: normalizedEmail }, { phone: normalizedPhone }],
      },
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: "User with this email or phone already exists",
      });
    }

    const hashedPassword = await bcryptjs.hash(password, 12);
    const verificationCode = generateVerificationCode();

    const user = await db.user.create({
      data: {
        firstName,
        lastName,
        name: `${firstName} ${lastName}`,
        email: normalizedEmail,
        phone: normalizedPhone,
        password: hashedPassword,
        role: UserRole.FIELD_OFFICER,
        status: UserStatus.PENDING,
        isApproved: false, // Needs admin approval
        token: verificationCode,
        emailVerified: false,
      },
    });

    await sendVerificationCodeResend({
      to: user.email,
      name: user.firstName,
      code: verificationCode,
    });

    return res.status(201).json({
      success: true,
      message: "Field officer registered. Awaiting admin approval after email verification.",
      data: {
        userId: user.id,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Field officer registration error:", error);
    return res.status(500).json({
      success: false,
      error: "Registration failed",
    });
  }
}

// ==================== LOGIN ====================

/**
 * Login user
 * POST /auth/login
 */
export async function login(req: Request, res: Response) {
  try {
    const { email, phone, password } = req.body;

    // Can login with either email or phone
    if ((!email && !phone) || !password) {
      return res.status(400).json({
        success: false,
        error: "Email/phone and password are required",
      });
    }

    // Find user by email or phone
    const user = await db.user.findFirst({
      where: {
        OR: [
          { email: email?.trim().toLowerCase() },
          { phone: phone?.trim().replace(/\s+/g, "") },
        ].filter(Boolean),
      },
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        error: "Invalid credentials",
      });
    }

    // Check password
    const isValidPassword = await bcryptjs.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        error: "Invalid credentials",
      });
    }

    // Check email verification
    if (!user.emailVerified) {
      return res.status(403).json({
        success: false,
        error: "Please verify your email first",
        code: "EMAIL_NOT_VERIFIED",
        data: { email: user.email },
      });
    }

    // Check user status
    if (user.status === UserStatus.SUSPENDED) {
      return res.status(403).json({
        success: false,
        error: "Your account has been suspended. Contact support.",
        code: "ACCOUNT_SUSPENDED",
      });
    }

    if (user.status === UserStatus.BANNED) {
      return res.status(403).json({
        success: false,
        error: "Your account has been banned.",
        code: "ACCOUNT_BANNED",
      });
    }

    if (user.status === UserStatus.INACTIVE || user.status === UserStatus.DEACTIVATED) {
      return res.status(403).json({
        success: false,
        error: "Your account is inactive.",
        code: "ACCOUNT_INACTIVE",
      });
    }

    // Check approval for roles that require it
    if (!user.isApproved && ["FIELD_OFFICER", "ADMIN", "MANAGER"].includes(user.role)) {
      return res.status(403).json({
        success: false,
        error: "Your account is pending approval",
        code: "PENDING_APPROVAL",
      });
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    // Store refresh token
    await db.refreshToken.create({
      data: {
        userId: user.id,
        token: refreshToken,
        expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
      },
    });

    // Update user status if pending
    if (user.status === UserStatus.PENDING) {
      await db.user.update({
        where: { id: user.id },
        data: { status: UserStatus.ACTIVE },
      });
    }

    // Log activity
    await db.activityLog.create({
      data: {
        userId: user.id,
        action: "USER_LOGIN",
        module: "auth",
        entityType: "User",
        entityId: user.id,
        status: "SUCCESS",
        description: `User logged in: ${user.email}`,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
      },
    });

    return res.status(200).json({
      success: true,
      message: "Login successful",
      data: {
        user: sanitizeUser({ ...user, status: UserStatus.ACTIVE }),
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({
      success: false,
      error: "Login failed. Please try again.",
    });
  }
}

// ==================== EMAIL VERIFICATION ====================

/**
 * Verify email with code
 * POST /auth/verify-email
 */
export async function verifyEmail(req: Request, res: Response) {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({
        success: false,
        error: "Email and verification code are required",
      });
    }

    const user = await db.user.findUnique({
      where: { email: email.trim().toLowerCase() },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    if (user.emailVerified) {
      return res.status(400).json({
        success: false,
        error: "Email already verified",
      });
    }

    if (!user.token || user.token !== code) {
      return res.status(400).json({
        success: false,
        error: "Invalid verification code",
      });
    }

    // Update user
    await db.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        status: user.isApproved ? UserStatus.ACTIVE : UserStatus.PENDING,
        token: null,
      },
    });

    // Log activity
    await db.activityLog.create({
      data: {
        userId: user.id,
        action: "EMAIL_VERIFIED",
        module: "auth",
        entityType: "User",
        entityId: user.id,
        status: "SUCCESS",
      },
    });

    // If user doesn't need approval, generate tokens
    if (user.isApproved) {
      const { accessToken, refreshToken } = generateTokens(user);

      await db.refreshToken.create({
        data: {
          userId: user.id,
          token: refreshToken,
          expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
        },
      });

      return res.status(200).json({
        success: true,
        message: "Email verified successfully",
        data: {
          user: sanitizeUser({ ...user, emailVerified: true, status: UserStatus.ACTIVE }),
          accessToken,
          refreshToken,
        },
      });
    }

    // For users needing approval
    return res.status(200).json({
      success: true,
      message: "Email verified. Your account is pending admin approval.",
      data: {
        userId: user.id,
        email: user.email,
        pendingApproval: true,
      },
    });
  } catch (error) {
    console.error("Email verification error:", error);
    return res.status(500).json({
      success: false,
      error: "Verification failed",
    });
  }
}

/**
 * Resend verification code
 * POST /auth/resend-verification
 */
export async function resendVerification(req: Request, res: Response) {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: "Email is required",
      });
    }

    const user = await db.user.findUnique({
      where: { email: email.trim().toLowerCase() },
    });

    // Don't reveal if user exists
    if (!user) {
      return res.status(200).json({
        success: true,
        message: "If the email exists, a verification code has been sent",
      });
    }

    if (user.emailVerified) {
      return res.status(400).json({
        success: false,
        error: "Email already verified",
      });
    }

    const newCode = generateVerificationCode();

    await db.user.update({
      where: { id: user.id },
      data: { token: newCode },
    });

    await sendVerificationCodeResend({
      to: user.email,
      name: user.firstName ?? user.name ?? "there",
      code: newCode,
    });

    return res.status(200).json({
      success: true,
      message: "Verification code sent",
    });
  } catch (error) {
    console.error("Resend verification error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to resend verification code",
    });
  }
}

// ==================== PASSWORD RESET ====================

/**
 * Request password reset
 * POST /auth/forgot-password
 */
export async function forgotPassword(req: Request, res: Response) {
  const genericResponse = {
    success: true,
    message: "If that email exists, a reset link has been sent",
  };

  try {
    const { email } = req.body;

    if (!email) {
      return res.status(200).json(genericResponse);
    }

    const user = await db.user.findUnique({
      where: { email: email.trim().toLowerCase() },
    });

    if (!user) {
      return res.status(200).json(genericResponse);
    }

    // Invalidate old tokens
    await db.passwordResetToken.deleteMany({
      where: { userId: user.id, usedAt: null },
    });

    // Create new token
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

    await db.passwordResetToken.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt: new Date(Date.now() + RESET_TTL_MIN * 60_000),
      },
    });

    const appUrl = process.env.APP_URL ?? "http://localhost:3000";
    const resetUrl = `${appUrl}/reset-password?token=${rawToken}&uid=${user.id}`;

    await sendResetEmailResend({
      to: user.email,
      name: user.firstName ?? user.name ?? "there",
      resetUrl,
    });

    // Log activity
    await db.activityLog.create({
      data: {
        userId: user.id,
        action: "PASSWORD_RESET_REQUESTED",
        module: "auth",
        entityType: "User",
        entityId: user.id,
        status: "SUCCESS",
      },
    });

    return res.status(200).json(genericResponse);
  } catch (error) {
    console.error("Forgot password error:", error);
    return res.status(200).json(genericResponse);
  }
}

/**
 * Reset password with token
 * POST /auth/reset-password
 */
export async function resetPassword(req: Request, res: Response) {
  try {
    const { uid, token, newPassword } = req.body;

    if (!uid || !token || !newPassword) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields",
      });
    }

    // Validate password strength
    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 8 characters",
      });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const record = await db.passwordResetToken.findFirst({
      where: { userId: uid, tokenHash },
    });

    if (!record || record.usedAt || record.expiresAt < new Date()) {
      return res.status(400).json({
        success: false,
        error: "Invalid or expired reset token",
      });
    }

    const hashedPassword = await bcryptjs.hash(newPassword, 12);

    await db.$transaction([
      db.user.update({
        where: { id: uid },
        data: { password: hashedPassword },
      }),
      db.passwordResetToken.update({
        where: { id: record.id },
        data: { usedAt: new Date() },
      }),
      // Revoke all sessions
      db.refreshToken.deleteMany({ where: { userId: uid } }),
    ]);

    // Log activity
    await db.activityLog.create({
      data: {
        userId: uid,
        action: "PASSWORD_RESET_COMPLETED",
        module: "auth",
        entityType: "User",
        entityId: uid,
        status: "SUCCESS",
      },
    });

    return res.status(200).json({
      success: true,
      message: "Password updated successfully",
    });
  } catch (error) {
    console.error("Reset password error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to reset password",
    });
  }
}

// ==================== TOKEN REFRESH ====================

/**
 * Refresh access token
 * POST /auth/refresh
 */
export async function refreshAccessToken(req: Request, res: Response) {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        error: "Refresh token is required",
      });
    }

    const tokenRecord = await db.refreshToken.findUnique({
      where: { token: refreshToken },
      include: { user: true },
    });

    if (!tokenRecord) {
      return res.status(401).json({
        success: false,
        error: "Invalid refresh token",
      });
    }

    if (tokenRecord.revoked || tokenRecord.expiresAt < new Date()) {
      // Delete expired/revoked token
      await db.refreshToken.delete({ where: { id: tokenRecord.id } });
      return res.status(401).json({
        success: false,
        error: "Refresh token expired or revoked",
      });
    }

    const user = tokenRecord.user;

    // Check user status
    if (user.status !== UserStatus.ACTIVE) {
      return res.status(403).json({
        success: false,
        error: "Account is not active",
      });
    }

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);

    // Rotate refresh token (delete old, create new)
    await db.$transaction([
      db.refreshToken.delete({ where: { id: tokenRecord.id } }),
      db.refreshToken.create({
        data: {
          userId: user.id,
          token: newRefreshToken,
          expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_MS),
        },
      }),
    ]);

    return res.status(200).json({
      success: true,
      data: {
        accessToken,
        refreshToken: newRefreshToken,
      },
    });
  } catch (error) {
    console.error("Token refresh error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to refresh token",
    });
  }
}

// ==================== LOGOUT ====================

/**
 * Logout user
 * POST /auth/logout
 */
export async function logout(req: Request, res: Response) {
  try {
    const { refreshToken } = req.body;
    const userId = (req as any).user?.id; // From auth middleware

    if (refreshToken) {
      // Revoke specific token
      await db.refreshToken.deleteMany({
        where: { token: refreshToken },
      });
    } else if (userId) {
      // Revoke all tokens for user
      await db.refreshToken.deleteMany({
        where: { userId },
      });
    }

    // Log activity
    if (userId) {
      await db.activityLog.create({
        data: {
          userId,
          action: "USER_LOGOUT",
          module: "auth",
          entityType: "User",
          entityId: userId,
          status: "SUCCESS",
        },
      });
    }

    return res.status(200).json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    console.error("Logout error:", error);
    return res.status(500).json({
      success: false,
      error: "Logout failed",
    });
  }
}

/**
 * Logout from all devices
 * POST /auth/logout-all
 */
export async function logoutAll(req: Request, res: Response) {
  try {
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        error: "Not authenticated",
      });
    }

    await db.refreshToken.deleteMany({
      where: { userId },
    });

    await db.activityLog.create({
      data: {
        userId,
        action: "USER_LOGOUT_ALL",
        module: "auth",
        entityType: "User",
        entityId: userId,
        status: "SUCCESS",
      },
    });

    return res.status(200).json({
      success: true,
      message: "Logged out from all devices",
    });
  } catch (error) {
    console.error("Logout all error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to logout from all devices",
    });
  }
}

// ==================== USER PROFILE ====================

/**
 * Get current user profile
 * GET /auth/me
 */
export async function getMe(req: Request, res: Response) {
  try {
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        error: "Not authenticated",
      });
    }

    const user = await db.user.findUnique({
      where: { id: userId },
      include: {
        // Include landlord profile if exists
        ownedLandlordProfile: {
          select: {
            id: true,
            landlordId: true,
            status: true,
            mouSigned: true,
            isVerified: true,
          },
        },
      },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    return res.status(200).json({
      success: true,
      data: {
        ...sanitizeUser(user),
        landlordProfile: user.ownedLandlordProfile,
      },
    });
  } catch (error) {
    console.error("Get me error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to get profile",
    });
  }
}

/**
 * Update current user profile
 * PATCH /auth/me
 */
export async function updateMe(req: Request, res: Response) {
  try {
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        error: "Not authenticated",
      });
    }

    const { firstName, lastName, phone, imageUrl, address, district, city } = req.body;

    const updateData: any = {};

    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;
    if (firstName || lastName) {
      const user = await db.user.findUnique({ where: { id: userId } });
      updateData.name = `${firstName ?? user?.firstName} ${lastName ?? user?.lastName}`;
    }
    if (phone) updateData.phone = phone.trim().replace(/\s+/g, "");
    if (imageUrl) updateData.imageUrl = imageUrl;
    if (address !== undefined) updateData.address = address;
    if (district !== undefined) updateData.district = district;
    if (city !== undefined) updateData.city = city;

    const user = await db.user.update({
      where: { id: userId },
      data: updateData,
    });

    await db.activityLog.create({
      data: {
        userId,
        action: "PROFILE_UPDATED",
        module: "auth",
        entityType: "User",
        entityId: userId,
        status: "SUCCESS",
      },
    });

    return res.status(200).json({
      success: true,
      message: "Profile updated",
      data: sanitizeUser(user),
    });
  } catch (error) {
    console.error("Update me error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to update profile",
    });
  }
}

/**
 * Change password
 * POST /auth/change-password
 */
export async function changePassword(req: Request, res: Response) {
  try {
    const userId = (req as any).user?.id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        error: "Not authenticated",
      });
    }

    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        error: "Current password and new password are required",
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: "New password must be at least 8 characters",
      });
    }

    const user = await db.user.findUnique({ where: { id: userId } });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    const isValid = await bcryptjs.compare(currentPassword, user.password);

    if (!isValid) {
      return res.status(400).json({
        success: false,
        error: "Current password is incorrect",
      });
    }

    const hashedPassword = await bcryptjs.hash(newPassword, 12);

    await db.$transaction([
      db.user.update({
        where: { id: userId },
        data: { password: hashedPassword },
      }),
      // Optionally revoke other sessions
      // db.refreshToken.deleteMany({ where: { userId } }),
    ]);

    await db.activityLog.create({
      data: {
        userId,
        action: "PASSWORD_CHANGED",
        module: "auth",
        entityType: "User",
        entityId: userId,
        status: "SUCCESS",
      },
    });

    return res.status(200).json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (error) {
    console.error("Change password error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to change password",
    });
  }
}

// ==================== ADMIN: USER APPROVAL ====================

/**
 * Approve a user (Admin only)
 * POST /auth/approve/:userId
 */
export async function approveUser(req: Request, res: Response) {
  try {
    const adminId = (req as any).user?.id;
    const { userId } = req.params;

    const user = await db.user.findUnique({ where: { id: userId } });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    if (user.isApproved) {
      return res.status(400).json({
        success: false,
        error: "User is already approved",
      });
    }

    await db.user.update({
      where: { id: userId },
      data: {
        isApproved: true,
        status: user.emailVerified ? UserStatus.ACTIVE : UserStatus.PENDING,
      },
    });

    // Create notification
    await db.notification.create({
      data: {
        userId: userId,
        type: "ACCOUNT_UPDATE",
        title: "Account Approved",
        message: "Your account has been approved. You can now log in.",
      },
    });

    await db.activityLog.create({
      data: {
        userId: adminId,
        action: "USER_APPROVED",
        module: "auth",
        entityType: "User",
        entityId: userId,
        status: "SUCCESS",
        description: `Admin approved user: ${user.email}`,
      },
    });

    return res.status(200).json({
      success: true,
      message: "User approved successfully",
    });
  } catch (error) {
    console.error("Approve user error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to approve user",
    });
  }
}

/**
 * Suspend a user (Admin only)
 * POST /auth/suspend/:userId
 */
export async function suspendUser(req: Request, res: Response) {
  try {
    const adminId = (req as any).user?.id;
    const { userId } = req.params;
    const { reason } = req.body;

    const user = await db.user.findUnique({ where: { id: userId } });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    await db.$transaction([
      db.user.update({
        where: { id: userId },
        data: { status: UserStatus.SUSPENDED },
      }),
      // Revoke all sessions
      db.refreshToken.deleteMany({ where: { userId } }),
    ]);

    await db.notification.create({
      data: {
        userId: userId,
        type: "ACCOUNT_UPDATE",
        title: "Account Suspended",
        message: reason ?? "Your account has been suspended. Contact support for more information.",
      },
    });

    await db.activityLog.create({
      data: {
        userId: adminId,
        action: "USER_SUSPENDED",
        module: "auth",
        entityType: "User",
        entityId: userId,
        status: "SUCCESS",
        description: `Admin suspended user: ${user.email}. Reason: ${reason ?? "Not specified"}`,
      },
    });

    return res.status(200).json({
      success: true,
      message: "User suspended",
    });
  } catch (error) {
    console.error("Suspend user error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to suspend user",
    });
  }
}

/**
 * Reactivate a suspended user (Admin only)
 * POST /auth/reactivate/:userId
 */
export async function reactivateUser(req: Request, res: Response) {
  try {
    const adminId = (req as any).user?.id;
    const { userId } = req.params;

    const user = await db.user.findUnique({ where: { id: userId } });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    if (user.status !== UserStatus.SUSPENDED) {
      return res.status(400).json({
        success: false,
        error: "User is not suspended",
      });
    }

    await db.user.update({
      where: { id: userId },
      data: { status: UserStatus.ACTIVE },
    });

    await db.notification.create({
      data: {
        userId: userId,
        type: "ACCOUNT_UPDATE",
        title: "Account Reactivated",
        message: "Your account has been reactivated. You can now log in.",
      },
    });

    await db.activityLog.create({
      data: {
        userId: adminId,
        action: "USER_REACTIVATED",
        module: "auth",
        entityType: "User",
        entityId: userId,
        status: "SUCCESS",
        description: `Admin reactivated user: ${user.email}`,
      },
    });

    return res.status(200).json({
      success: true,
      message: "User reactivated",
    });
  } catch (error) {
    console.error("Reactivate user error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to reactivate user",
    });
  }
}