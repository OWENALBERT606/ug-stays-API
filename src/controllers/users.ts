


import { db } from "@/db/db";
import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import crypto, { randomInt } from "crypto";
import {
  generateAccessToken,
  generateRefreshToken,
  TokenPayload,
} from "@/utils/tokens";
import { AuthRequest } from "@/utils/auth";
import { UserRole, UserStatus } from "@prisma/client";
import { sendVerificationCodeResend } from "@/lib/mailer";



function generateAccountNumber(): string {
  return `GK${randomInt(1_000_000, 10_000_000)}`;
}


/* Helpers */
const isValidRole = (v: any): v is UserRole =>
  Object.values(UserRole).includes(v as UserRole);
const isValidStatus = (v: any): v is UserStatus =>
  Object.values(UserStatus).includes(v as UserStatus);

// Secure 6-digit numeric code, zero-padded
const makeSixDigitToken = () =>
  String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");


export async function createUser(req: Request, res: Response) {
  const {
    email,
    phone,
    password,
    firstName,
    lastName,
    imageUrl,            // optional
    role,                // optional
    status,              // optional
  } = req.body as {
    email: string;
    phone: string;
    password: string;
    firstName: string;
    lastName: string;
    imageUrl?: string;
    role?: UserRole | string;
    status?: UserStatus | string;
  };

  try {
    // Basic validation
    if (!email || !phone || !password || !firstName || !lastName) {
      return res.status(400).json({ data: null, error: "Missing required fields." });
    }

    // ✅ Password length validation (minimum 6 characters)
if (password.length < 6) {
  return res.status(400).json({ 
    data: null, 
    error: "Password must be at least 6 characters long." 
  });
}

    const emailNorm = email.trim().toLowerCase();
    const phoneNorm = phone.trim();
    const roleValue: UserRole = isValidRole(role) ? (role as UserRole) : UserRole.TENANT;
    const statusValue: UserStatus = isValidStatus(status) ? (status as UserStatus) : UserStatus.ACTIVE;

    // Pre-check (optional but gives nicer error than catching P2002)
    const existing = await db.user.findFirst({
      where: { OR: [{ email: emailNorm }, { phone: phoneNorm }] },
      select: { id: true },
    });
    if (existing) {
      return res
        .status(409)
        .json({ data: null, error: "User with this email or phone already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const verificationCode = makeSixDigitToken();

    // Defaults for the new wallet
    // const bankFee = 30;
    // const transactionFee = 10;
    // const feeAtBank = 10;
    // const totalFees = bankFee + transactionFee + feeAtBank;
    // const netAssetValue = 0 - totalFees;

    // Retry whole transaction a couple times for rare, concurrent accountNumber collisions
    let newUser:
      | {
          id: string;
          firstName: string | null;
          lastName: string | null;
          name: string | null;
          email: string;
          phone: string | null;
          imageUrl: string | null;
          role: UserRole;
          status: UserStatus;
          createdAt: Date;
          updatedAt: Date;
        }
      | undefined;

    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        newUser = await db.$transaction(async (tx) => {
          const accountNumber = await generateAccountNumber();

          const user = await tx.user.create({
            data: {
              email: emailNorm,
              phone: phoneNorm,
              firstName,
              lastName,
              name: `${firstName} ${lastName}`.trim(),
              imageUrl, // let Prisma default if undefined
              password: hashedPassword,
              role: roleValue,
              status: statusValue, // typically PENDING until verification
              emailVerified: true,
              isApproved: true,
              token: verificationCode, // store 6-digit code for email verification
            },
            select: {
              id: true,
              firstName: true,
              lastName: true,
              name: true,
              email: true,
              phone: true,
              imageUrl: true,
              role: true,
              status: true,
              createdAt: true,
              updatedAt: true,
            },
          });

          return user;
        });

        // success -> break retry loop
        break;
      } catch (err: any) {
        // Re-try only if this looks like a unique violation (e.g., accountNumber race)
        if (err?.code === "P2002" && attempt < 2) {
          continue;
        }
        throw err;
      }
    }

    // Should never be undefined here
    if (!newUser) {
      return res.status(500).json({ data: null, error: "Failed to create user." });
    }

    // Send verification email AFTER the DB commit
    await sendVerificationCodeResend({
      to: newUser.email,
      name: newUser.firstName ?? newUser.name ?? "there",
      code: verificationCode,
    });

    return res.status(201).json({ data: newUser, error: null });
  } catch (error: any) {
    if (error?.code === "P2002") {
      // Unique constraint violation (email/phone/accountNumber)
      return res.status(409).json({ data: null, error: "Email or phone already in use" });
    }
    console.error("Error creating user:", error);
    return res.status(500).json({ data: null, error: "Something went wrong" });
  }
}


/* ======================
   LOGIN USER (email or phone)
====================== */
export async function loginUser(req: Request, res: Response) {
  const { identifier, password } = req.body as { identifier: string; password: string };

  try {
    if (!identifier || !password) {
      return res.status(400).json({ data: null, error: "Missing credentials" });
    }

    const idNorm = identifier.trim().toLowerCase();
    const user = await db.user.findFirst({
      where: {
        OR: [{ email: idNorm }, { phone: identifier.trim() }],
      },
    });

    if (!user) {
      return res.status(401).json({ data: null, error: "Invalid credentials" });
    }

    if (user.status !== "ACTIVE") {
      return res.status(403).json({ data: null, error: "User account is not active" });
    }

    if (!user.password) {
      return res
        .status(401)
        .json({ data: null, error: "This account has no password. Use social login or reset password." });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.status(401).json({ data: null, error: "Invalid credentials" });
    }

    const payload: TokenPayload = {
      userId: user.id,
      phone: user.phone,
      email: user.email,
      role: user.role,
    };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    await db.refreshToken.create({
      data: {
        token: refreshToken,
        userId: user.id,
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      },
    });

    const { password: _pw, ...safe } = user;
    return res.status(200).json({
      data: { user: safe, accessToken, refreshToken },
      error: null,
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ data: null, error: "An error occurred during login" });
  }
}

/* ======================
   GET ALL USERS
====================== */
export async function getAllUsers(req: AuthRequest, res: Response) {
  try {
    const users = await db.user.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        accounts: true,
        sessions: false,
        refreshTokens: false,
      },
    });
    const safe = users.map(({ password, ...u }) => u);
    return res.status(200).json({ data: safe, error: null });
  } catch (error) {
    console.error("Error fetching users:", error);
    return res.status(500).json({ data: null, error: "Failed to fetch users" });
  }
}

/* ======================
   GET CURRENT USER
====================== */
export async function getCurrentUser(req: AuthRequest, res: Response) {
  try {
    if (!req.user?.userId) {
      return res.status(401).json({ data: null, error: "Unauthorized" });
    }

    const user = await db.user.findUnique({
      where: { id: req.user.userId },
        select: {
        id: true,
        firstName: true,
        lastName: true,
        name: true,
        email: true,
        phone: true,
         emailVerified: true, // ⬅️ add
        status: true,      // ⬅️ add
        isApproved: true,  
        imageUrl: true,
        role: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) return res.status(404).json({ data: null, error: "User not found" });
    return res.status(200).json({ data: user, error: null });
  } catch (error) {
    console.error("Error fetching current user:", error);
    return res.status(500).json({ data: null, error: "Server error" });
  }
}

/* ======================
   SOFT DELETE USER (status -> DEACTIVATED)
====================== */
export async function deleteUser(req: AuthRequest, res: Response) {
  const { id } = req.params;

  try {
    const existingUser = await db.user.findUnique({ where: { id } });
    if (!existingUser) return res.status(404).json({ data: null, error: "User not found" });

    await db.user.update({
      where: { id },
      data: { status: UserStatus.DEACTIVATED },
    });

    return res.status(200).json({ data: null, message: "User deactivated successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    return res.status(500).json({ data: null, error: "Failed to delete user" });
  }
}

/* ======================
   GET USER BY ID
====================== */
export async function getUserById(req: Request, res: Response) {
  const { id } = req.params;

  try {
    const user = await db.user.findUnique({
      where: { id },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        name: true,
        email: true,
        phone: true,
         emailVerified: true, // ⬅️ add
        status: true,      // ⬅️ add
        isApproved: true,  
        imageUrl: true,
        role: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      return res.status(404).json({ data: null, error: "User not found" });
    }

    return res.status(200).json({ data: user, error: null });
  } catch (error) {
    console.error("Error fetching user by id:", error);
    return res.status(500).json({ data: null, error: "Server error" });
  }
}



export async function updateUser(req: Request, res: Response) {
  const { id } = req.params;
  const {
    firstName,
    lastName,
    email,
    phone,
    role,
    status,
    password,
    imageUrl,
    // ⬇️ add these
    emailVerified,
    isActive,
    isApproved,
  } = req.body as {
    firstName?: string;
    lastName?: string;
    email?: string;
    phone?: string;
    role?: UserRole | string;
    status?: UserStatus | string;
    password?: string;
    imageUrl?: string;
    emailVerified?: boolean;
    isActive?: boolean;
    isApproved?: boolean;
  };

  try {
    const existingUser = await db.user.findUnique({ where: { id } });
    if (!existingUser) return res.status(404).json({ data: null, error: "User not found" });

    // unique checks
    if (email || phone) {
      const emailNorm = email?.trim().toLowerCase();
      const phoneNorm = phone?.trim();
      const conflict = await db.user.findFirst({
        where: {
          OR: [{ email: emailNorm ?? undefined }, { phone: phoneNorm ?? undefined }],
          NOT: { id },
        },
        select: { id: true },
      });
      if (conflict) {
        return res.status(409).json({ data: null, error: "Email or phone already in use by another user" });
      }
    }

    const roleValue = role !== undefined ? (isValidRole(role) ? (role as UserRole) : undefined) : undefined;
    const statusValue = status !== undefined ? (isValidStatus(status) ? (status as UserStatus) : undefined) : undefined;
    const hashedPassword = password ? await bcrypt.hash(password, 12) : undefined;

    const nextFirst = firstName ?? existingUser.firstName;
    const nextLast = lastName ?? existingUser.lastName;

    const updatedUser = await db.user.update({
      where: { id },
      data: {
        firstName: nextFirst,
        lastName: nextLast,
        name: `${nextFirst} ${nextLast}`.trim(),
        email: email ? email.trim().toLowerCase() : existingUser.email,
        phone: phone ? phone.trim() : existingUser.phone,
        role: roleValue ?? existingUser.role,
        status: statusValue ?? existingUser.status,
        password: hashedPassword ?? existingUser.password,
        imageUrl: imageUrl ?? existingUser.imageUrl,
        // ⬇️ persist toggles
        emailVerified: emailVerified ?? existingUser.emailVerified,        isApproved: isApproved ?? existingUser.isApproved,
      },
      select: {
        id: true,
        firstName: true,
        lastName: true,
        name: true,
        email: true,
        phone: true,
        role: true,
        status: true,
        imageUrl: true,
        emailVerified: true,
        isApproved: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return res.status(200).json({ data: updatedUser, error: null });
  } catch (error) {
    console.error("Error updating user:", error);
    return res.status(500).json({ data: null, error: "Failed to update user" });
  }
}
