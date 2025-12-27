
// src/routes/user.routes.ts
import { createUser, deleteUser, getAllUsers, getCurrentUser, getUserById, loginUser, updateUser } from "@/controllers/users";
import { authenticateToken } from "@/utils/auth";
import express from "express";
import rateLimit from "express-rate-limit";

const userRouter = express.Router();

// 🔹 Login-specific limiter (5 attempts per 15 minutes per IP)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // max attempts per window
  message: {
    status: 429,
    error: "Too many login attempts. Please try again after 15 minutes.",
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Routes
userRouter.post("/register", createUser);
userRouter.post("/login", loginLimiter, loginUser); // ✅ limiter applied here
userRouter.get("/users", getAllUsers);
userRouter.delete("/users/:id", deleteUser);
userRouter.get("/me", authenticateToken, getCurrentUser);
userRouter.get("/users/:id", getUserById); // ✅ fetch by ID
userRouter.put("/users/:id", updateUser); // ✅ update user

export default userRouter;
