// redis.ts
import { createClient } from "redis";

const redisURL = process.env.REDIS_URL || "redis://redis:6379";
const redisClient = createClient({
  url: redisURL,
});

redisClient.on("error", (err: unknown) =>
  console.log("Redis Client Error", err)
);

redisClient.connect().catch((err: unknown) => {
  console.error("Redis connection error:", err);
});

export default redisClient;
