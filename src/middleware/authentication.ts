import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { createClient, RedisClientType } from "redis";
import { ERROR_MESSAGES } from "../constants/messages";

// Define a decoded token interface.
interface DecodedToken extends jwt.JwtPayload {
  id: string;
  [key: string]: any;
}

// Extend Express Request to include an optional "user" property.
interface AuthenticatedRequest extends Request {
  user?: DecodedToken;
}

class AuthenticationMiddleware {
  private redisClient: RedisClientType;
  private readonly accessTokenSecret: string;

  constructor() {
    // Ensure the ACCESS_TOKEN_SECRET is defined.
    if (!process.env.ACCESS_TOKEN_SECRET) {
      throw new Error("ACCESS_TOKEN_SECRET is not defined");
    }
    this.accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;

    // Use REDIS_URL from environment, or fallback to the Docker service name.
    this.redisClient = createClient({ url: process.env.REDIS_URL || "redis://redis:6379" });
    this.initializeRedis();
  }

  // Asynchronously initialize the Redis connection.
  private async initializeRedis(): Promise<void> {
    try {
      await this.redisClient.connect();
      console.log("Connected to Redis");
    } catch (error) {
      console.error("Redis connection error:", error);
    }
  }

  // Extract the token from an Authorization header ("Bearer <token>").
  private extractToken(authHeader?: string): string | null {
    if (authHeader && authHeader.startsWith("Bearer ")) {
      return authHeader.split(" ")[1];
    }
    return null;
  }

  // Check if a token is blacklisted by looking it up in Redis.
  private async isTokenBlacklisted(token: string): Promise<boolean> {
    try {
      const value = await this.redisClient.get(`bl_${token}`);
      return value === "1";
    } catch (error) {
      console.error("Redis error while checking token blacklist:", error);
      // Fail secure: if there is an error checking Redis, treat the token as blacklisted.
      return true;
    }
  }

  // Middleware function to authenticate incoming requests.
  public authenticate = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const token = this.extractToken(req.headers.authorization);
    if (!token) {
      res.status(401).json({ error: ERROR_MESSAGES.UNAUTHORIZED });
      return;
    }

    // Reject the request if the token is blacklisted.
    if (await this.isTokenBlacklisted(token)) {
      res.status(401).json({ error: ERROR_MESSAGES.UNAUTHORIZED });
      return;
    }

    try {
      // Verify the token and attach the decoded payload to the request.
      const decoded = jwt.verify(token, this.accessTokenSecret) as DecodedToken;
      req.user = decoded;
      next();
    } catch (error) {
      res.status(401).json({ error: ERROR_MESSAGES.UNAUTHORIZED });
    }
  };
}

// Create an instance of the middleware and export its authenticate function.
const authMiddlewareInstance = new AuthenticationMiddleware();
export const authMiddleware = authMiddlewareInstance;
export const authenticate = authMiddlewareInstance.authenticate;
