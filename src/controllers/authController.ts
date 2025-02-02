import bcrypt from "bcrypt";
import { Request, Response } from "express";
import User from "../models/User";
import redisClient from "../redis";
import { SUCCESS_MESSAGES, ERROR_MESSAGES } from "../constants/messages";
import { generateAccessToken, generateRefreshToken } from "../utils/jwt";

/**
 * POST /auth/signup
 * Creates a new user.
 */
export const signup = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  // Validate payload
  if (!email || !password) {
    res.status(400).json({ error: ERROR_MESSAGES.VALIDATION_FAILED });
    return;
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      email,
      password: hashedPassword,
    });

    await user.save();
    res.status(201).json({ message: SUCCESS_MESSAGES.USER_CREATED });
  } catch (err: any) {
    // Duplicate key error (e.g. email already exists)
    if (err.code === 11000) {
      res.status(400).json({ error: ERROR_MESSAGES.SIGNUP_FAILED });
    } else {
      res.status(500).json({ error: ERROR_MESSAGES.INTERNAL_SERVER_ERROR });
    }
  }
};

/**
 * POST /auth/login
 * Authenticates the user and returns an access token (and sets a refresh token cookie).
 */
export const login = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  // Validate payload
  if (!email || !password) {
    res.status(400).json({ error: ERROR_MESSAGES.VALIDATION_FAILED });
    return;
  }

  try {
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      res.status(401).json({ error: ERROR_MESSAGES.INVALID_CREDENTIALS });
      return;
    }

    const accessToken = generateAccessToken(user._id.toString());
    const refreshToken = generateRefreshToken(user._id.toString());

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    res.status(200).json({
      message: SUCCESS_MESSAGES.LOGIN_SUCCESSFUL,
      accessToken,
    });
  } catch (error) {
    res.status(500).json({ error: ERROR_MESSAGES.INTERNAL_SERVER_ERROR });
  }
};

export const logout = async (req: Request, res: Response): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({ error: ERROR_MESSAGES.UNAUTHORIZED });
      return;
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      res.status(401).json({ error: ERROR_MESSAGES.UNAUTHORIZED });
      return;
    }

    await redisClient.set(`bl_${token}`, "1", { EX: 24 * 60 * 60 });

    res.clearCookie("refreshToken");

    // Respond with 204 No Content to indicate a successful logout.
    res.sendStatus(204);
  } catch (error) {
    res.status(500).json({ error: ERROR_MESSAGES.INTERNAL_SERVER_ERROR });
  }
};
