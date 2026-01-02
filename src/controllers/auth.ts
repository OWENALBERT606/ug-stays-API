

// controllers/auth.controller.ts
import { Request, Response } from "express";
import crypto from "crypto";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";
import { db } from "@/db/db";
import { sendResetEmailResend } from "@/utils/mailer";
import { sendVerificationCodeResend } from "@/lib/mailer";
import { UserRole, UserStatus } from "@prisma/client";

// ==================== CONFIG ====================
const ACCESS_TOKEN_TTL = "7d"; // 7 days
const REFRESH_TOKEN_DAYS = 30;
const REFRESH_TOKEN_TTL_MS = 1000 * 60 * 60 * 24 * REFRESH_TOKEN_DAYS;
const RESET_TTL_MIN = 30;
const VERIFICATION_CODE_LENGTH = 6;

// Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ==================== HELPER FUNCTIONS ====================

function generateVerificationCode(): string {
  return String(crypto.randomInt(0, 1_000_000)).padStart(VERIFICATION_CODE_LENGTH, "0");
}

function generateTokens(user: { id: string; email: string; role: UserRole }) {
  const accessToken = jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET!,
    { expiresIn: ACCESS_TOKEN_TTL }
  );

  const refreshToken = crypto.randomUUID();

  return { accessToken, refreshToken };
}

function sanitizeUser(user: any) {
  const { password, token, ...sanitized } = user;
  return {
    id: sanitized.id,
    userId: sanitized.userId,
    email: sanitized.email,
    phone: sanitized.phone,
    role: sanitized.role,
    status: sanitized.status,
    firstName: sanitized.firstName,
    lastName: sanitized.lastName,
    name: sanitized.name,
    imageUrl: sanitized.imageUrl,
    emailVerified: sanitized.emailVerified,
    isApproved: sanitized.isApproved,
    createdAt: sanitized.createdAt,
  };
}

// ==================== REGISTER WITH CREDENTIALS ====================

/**
 * Register a new user with email/phone and password
 * POST /api/v1/auth/register
 */
export async function register(req: Request, res: Response) {
  try {
    const {
      firstName,
      lastName,
      email,
      phone,
      password,
      role = UserRole.TENANT,
    } = req.body;

    // Validation
    if (!firstName || !lastName || !email || !phone || !password) {
      return res.status(400).json({
        success: false,
        error: "All fields are required: firstName, lastName, email, phone, password",
      });
    }

    // Password validation
    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 8 characters",
      });
    }

    // Normalize
    const normalizedEmail = email.trim().toLowerCase();
    const normalizedPhone = phone.trim().replace(/\s+/g, "");

    // Check existing user
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

    // Determine if approval is needed
    const rolesRequiringApproval: UserRole[] = [
      UserRole.FIELD_OFFICER,
      UserRole.ADMIN,
      UserRole.MANAGER,
    ];
    const requiresApproval = rolesRequiringApproval.includes(role as UserRole);

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
        status: UserStatus.PENDING,
        isApproved: !requiresApproval,
        token: verificationCode,
        emailVerified: false,
      },
    });

    // Send verification email
    try {
      await sendVerificationCodeResend({
        to: user.email,
        name: user.firstName,
        code: verificationCode,
      });
    } catch (emailError) {
      console.error("Failed to send verification email:", emailError);
    }

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
 * Register a Field Officer
 * POST /api/v1/auth/register/field-officer
 */
export async function registerFieldOfficer(req: Request, res: Response) {
  try {
    const { firstName, lastName, email, phone, password } = req.body;

    if (!firstName || !lastName || !email || !phone || !password) {
      return res.status(400).json({
        success: false,
        error: "All fields are required",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const normalizedPhone = phone.trim().replace(/\s+/g, "");

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
        isApproved: false,
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

// ==================== LOGIN WITH CREDENTIALS ====================

/**
 * Login with email/phone and password
 * POST /api/v1/auth/login
 */
export async function login(req: Request, res: Response) {
  try {
    const { email, phone, password } = req.body;

    if ((!email && !phone) || !password) {
      return res.status(400).json({
        success: false,
        error: "Email/phone and password are required",
      });
    }

    // Find user
    const whereConditions = [];
    if (email) whereConditions.push({ email: email.trim().toLowerCase() });
    if (phone) whereConditions.push({ phone: phone.trim().replace(/\s+/g, "") });

    const user = await db.user.findFirst({
      where: { OR: whereConditions },
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        error: "Invalid credentials",
      });
    }

    // Check if user has password (might be OAuth-only account)
    if (!user.password) {
      return res.status(401).json({
        success: false,
        error: "This account uses Google Sign-In. Please login with Google.",
        code: "OAUTH_ACCOUNT",
      });
    }

    // Verify password
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
    const statusErrors: Record<string, { error: string; code: string }> = {
      [UserStatus.SUSPENDED]: {
        error: "Your account has been suspended. Contact support.",
        code: "ACCOUNT_SUSPENDED",
      },
      [UserStatus.BANNED]: {
        error: "Your account has been banned.",
        code: "ACCOUNT_BANNED",
      },
      [UserStatus.INACTIVE]: {
        error: "Your account is inactive.",
        code: "ACCOUNT_INACTIVE",
      },
      [UserStatus.DEACTIVATED]: {
        error: "Your account has been deactivated.",
        code: "ACCOUNT_DEACTIVATED",
      },
    };

    if (statusErrors[user.status]) {
      return res.status(403).json({
        success: false,
        ...statusErrors[user.status],
      });
    }

    // Check approval for certain roles
    const rolesRequiringApproval = ["FIELD_OFFICER", "ADMIN", "MANAGER"];
    if (!user.isApproved && rolesRequiringApproval.includes(user.role)) {
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

    // Update status if pending
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

// ==================== GOOGLE OAUTH ====================

/**
 * Sign in/up with Google
 * POST /api/v1/auth/google
 */
export async function googleAuth(req: Request, res: Response) {
  try {
    const { idToken, role = UserRole.TENANT } = req.body;

    if (!idToken) {
      return res.status(400).json({
        success: false,
        error: "Google ID token is required",
      });
    }

    // Verify the Google ID token
    let payload;
    try {
      const ticket = await googleClient.verifyIdToken({
        idToken,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
      payload = ticket.getPayload();
    } catch (verifyError) {
      console.error("Google token verification failed:", verifyError);
      return res.status(401).json({
        success: false,
        error: "Invalid Google token",
      });
    }

    if (!payload || !payload.email) {
      return res.status(401).json({
        success: false,
        error: "Could not get user info from Google",
      });
    }

    const { email, given_name, family_name, picture, sub: googleId } = payload;
    const normalizedEmail = email.toLowerCase();

    // Check if user exists
    let user = await db.user.findUnique({
      where: { email: normalizedEmail },
      include: {
        accounts: {
          where: { provider: "google" },
        },
      },
    });

    if (user) {
      // User exists - check if Google account is linked
      const hasGoogleAccount = user.accounts.length > 0;

      if (!hasGoogleAccount) {
        // Link Google account to existing user
        await db.account.create({
          data: {
            userId: user.id,
            type: "oauth",
            provider: "google",
            providerAccountId: googleId!,
            access_token: idToken,
          },
        });

        // Update user info if missing
        await db.user.update({
          where: { id: user.id },
          data: {
            emailVerified: true, // Google emails are verified
            imageUrl: user.imageUrl || picture,
            firstName: user.firstName || given_name,
            lastName: user.lastName || family_name,
            name: user.name || `${given_name} ${family_name}`,
          },
        });
      }

      // Check user status
      if (user.status === UserStatus.SUSPENDED || user.status === UserStatus.BANNED) {
        return res.status(403).json({
          success: false,
          error: "Your account has been suspended or banned",
          code: "ACCOUNT_BLOCKED",
        });
      }

      // Check approval for certain roles
      if (!user.isApproved && ["FIELD_OFFICER", "ADMIN", "MANAGER"].includes(user.role)) {
        return res.status(403).json({
          success: false,
          error: "Your account is pending approval",
          code: "PENDING_APPROVAL",
        });
      }

      // Update status if needed
      if (user.status === UserStatus.PENDING || user.status === UserStatus.INACTIVE) {
        await db.user.update({
          where: { id: user.id },
          data: { status: UserStatus.ACTIVE, emailVerified: true },
        });
        user.status = UserStatus.ACTIVE;
        user.emailVerified = true;
      }
    } else {
      // Create new user
      const rolesRequiringApproval = ["FIELD_OFFICER", "ADMIN", "MANAGER"];

     const requiresApproval = rolesRequiringApproval.includes(role as string);

      user = await db.user.create({
        data: {
          email: normalizedEmail,
          firstName: given_name || "",
          lastName: family_name || "",
          name: `${given_name || ""} ${family_name || ""}`.trim() || normalizedEmail,
          phone: null, // Will need to be added later
          imageUrl: picture,
          role: role as UserRole,
          status: UserStatus.ACTIVE,
          emailVerified: true, // Google emails are verified
          isApproved: !requiresApproval,
          password: null, // No password for OAuth users
          accounts: {
            create: {
              type: "oauth",
              provider: "google",
              providerAccountId: googleId!,
              access_token: idToken,
            },
          },
        },
        include: {
          accounts: true,
        },
      });

      // Log activity
      await db.activityLog.create({
        data: {
          userId: user.id,
          action: "USER_REGISTERED_GOOGLE",
          module: "auth",
          entityType: "User",
          entityId: user.id,
          status: "SUCCESS",
          description: `New user registered via Google: ${user.email}`,
        },
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

    // Log activity
    await db.activityLog.create({
      data: {
        userId: user.id,
        action: "USER_LOGIN_GOOGLE",
        module: "auth",
        entityType: "User",
        entityId: user.id,
        status: "SUCCESS",
        description: `User logged in via Google: ${user.email}`,
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"],
      },
    });

    // Check if phone is missing (needs to be added)
    const needsPhone = !user.phone;

    return res.status(200).json({
      success: true,
      message: user.accounts?.length === 1 ? "Account created successfully" : "Login successful",
      data: {
        user: sanitizeUser(user),
        accessToken,
        refreshToken,
        needsPhone, // Frontend should prompt for phone if true
      },
    });
  } catch (error) {
    console.error("Google auth error:", error);
    return res.status(500).json({
      success: false,
      error: "Authentication failed. Please try again.",
    });
  }
}

/**
 * Add phone number to Google OAuth user
 * POST /api/v1/auth/add-phone
 */
export async function addPhoneNumber(req: Request, res: Response) {
  try {
    const userId = (req as any).user?.userId;
    const { phone } = req.body;

    if (!userId) {
      return res.status(401).json({
        success: false,
        error: "Not authenticated",
      });
    }

    if (!phone) {
      return res.status(400).json({
        success: false,
        error: "Phone number is required",
      });
    }

    const normalizedPhone = phone.trim().replace(/\s+/g, "");

    // Check if phone already exists
    const existingUser = await db.user.findFirst({
      where: {
        phone: normalizedPhone,
        NOT: { id: userId },
      },
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: "This phone number is already in use",
      });
    }

    const user = await db.user.update({
      where: { id: userId },
      data: { phone: normalizedPhone },
    });

    return res.status(200).json({
      success: true,
      message: "Phone number added successfully",
      data: sanitizeUser(user),
    });
  } catch (error) {
    console.error("Add phone error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to add phone number",
    });
  }
}

// ==================== EMAIL VERIFICATION ====================

/**
 * Verify email with code
 * POST /api/v1/auth/verify-email
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
 * POST /api/v1/auth/resend-verification
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
 * POST /api/v1/auth/forgot-password
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
 * POST /api/v1/auth/reset-password
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
      db.refreshToken.deleteMany({ where: { userId: uid } }),
    ]);

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
 * POST /api/v1/auth/refresh
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
      await db.refreshToken.delete({ where: { id: tokenRecord.id } });
      return res.status(401).json({
        success: false,
        error: "Refresh token expired or revoked",
      });
    }

    const user = tokenRecord.user;

    if (user.status !== UserStatus.ACTIVE) {
      return res.status(403).json({
        success: false,
        error: "Account is not active",
      });
    }

    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);

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
 * POST /api/v1/auth/logout
 */
export async function logout(req: Request, res: Response) {
  try {
    const { refreshToken } = req.body;
    const userId = (req as any).user?.userId;

    if (refreshToken) {
      await db.refreshToken.deleteMany({
        where: { token: refreshToken },
      });
    } else if (userId) {
      await db.refreshToken.deleteMany({
        where: { userId },
      });
    }

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
 * POST /api/v1/auth/logout-all
 */
export async function logoutAll(req: Request, res: Response) {
  try {
    const userId = (req as any).user?.userId;

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
 * GET /api/v1/auth/me
 */
export async function getMe(req: Request, res: Response) {
  try {
    const userId = (req as any).user?.userId;

    if (!userId) {
      return res.status(401).json({
        success: false,
        error: "Not authenticated",
      });
    }

    const user = await db.user.findUnique({
      where: { id: userId },
      include: {
        ownedLandlordProfile: {
          select: {
            id: true,
            landlordId: true,
            status: true,
            mouSigned: true,
            isVerified: true,
          },
        },
        accounts: {
          select: {
            provider: true,
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
        linkedAccounts: user.accounts.map((a) => a.provider),
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
 * PATCH /api/v1/auth/me
 */
export async function updateMe(req: Request, res: Response) {
  try {
    const userId = (req as any).user?.userId;

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
      const existingUser = await db.user.findUnique({ where: { id: userId } });
      updateData.name = `${firstName ?? existingUser?.firstName} ${lastName ?? existingUser?.lastName}`;
    }
    if (phone) {
      const normalizedPhone = phone.trim().replace(/\s+/g, "");
      const existingPhone = await db.user.findFirst({
        where: { phone: normalizedPhone, NOT: { id: userId } },
      });
      if (existingPhone) {
        return res.status(409).json({
          success: false,
          error: "Phone number already in use",
        });
      }
      updateData.phone = normalizedPhone;
    }
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
 * POST /api/v1/auth/change-password
 */
export async function changePassword(req: Request, res: Response) {
  try {
    const userId = (req as any).user?.userId;

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

    // Check if user has a password (OAuth users might not)
    if (!user.password) {
      return res.status(400).json({
        success: false,
        error: "Cannot change password for OAuth accounts. Please set a password first.",
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

    await db.user.update({
      where: { id: userId },
      data: { password: hashedPassword },
    });

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

/**
 * Set password for OAuth user
 * POST /api/v1/auth/set-password
 */
export async function setPassword(req: Request, res: Response) {
  try {
    const userId = (req as any).user?.userId;

    if (!userId) {
      return res.status(401).json({
        success: false,
        error: "Not authenticated",
      });
    }

    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: "Password must be at least 8 characters",
      });
    }

    const user = await db.user.findUnique({ where: { id: userId } });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    if (user.password) {
      return res.status(400).json({
        success: false,
        error: "Password already set. Use change password instead.",
      });
    }

    const hashedPassword = await bcryptjs.hash(newPassword, 12);

    await db.user.update({
      where: { id: userId },
      data: { password: hashedPassword },
    });

    await db.activityLog.create({
      data: {
        userId,
        action: "PASSWORD_SET",
        module: "auth",
        entityType: "User",
        entityId: userId,
        status: "SUCCESS",
      },
    });

    return res.status(200).json({
      success: true,
      message: "Password set successfully",
    });
  } catch (error) {
    console.error("Set password error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to set password",
    });
  }
}

// ==================== ADMIN: USER MANAGEMENT ====================

/**
 * Approve a user (Admin only)
 * POST /api/v1/auth/approve/:userId
 */
export async function approveUser(req: Request, res: Response) {
  try {
    const adminId = (req as any).user?.userId;
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
 * POST /api/v1/auth/suspend/:userId
 */
export async function suspendUser(req: Request, res: Response) {
  try {
    const adminId = (req as any).user?.userId;
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
 * POST /api/v1/auth/reactivate/:userId
 */
export async function reactivateUser(req: Request, res: Response) {
  try {
    const adminId = (req as any).user?.userId;
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



export async function completeProfile(req: Request, res: Response) {
  try {
    const { email, district, city, address } = req.body;

    // Validate email
    if (!email) {
      return res.status(400).json({
        success: false,
        error: "Email is required",
      });
    }

    // Find user by email
    const user = await db.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    // Only allow completing profile for verified users
    if (!user.emailVerified) {
      return res.status(403).json({
        success: false,
        error: "Please verify your email first",
      });
    }

    // Build update data - only allow safe fields
    const updateData: any = {};
    
    if (district !== undefined) {
      updateData.district = district || null;
    }
    if (city !== undefined) {
      updateData.city = city || null;
    }
    if (address !== undefined) {
      updateData.address = address || null;
    }

    // Only update if there's something to update
    if (Object.keys(updateData).length === 0) {
      return res.status(200).json({
        success: true,
        message: "No changes to update",
      });
    }

    // Update user
    await db.user.update({
      where: { id: user.id },
      data: updateData,
    });

    // Log activity
    await db.activityLog.create({
      data: {
        userId: user.id,
        action: "PROFILE_COMPLETED",
        module: "auth",
        entityType: "User",
        entityId: user.id,
        status: "SUCCESS",
        description: "User completed profile during registration",
      },
    });

    return res.status(200).json({
      success: true,
      message: "Profile updated successfully",
    });

  } catch (error: any) {
    console.error("Complete profile error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to update profile",
    });
  }
}