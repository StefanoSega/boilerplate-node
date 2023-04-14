import * as redis from "redis";

import { CacheService } from "./cacheService";

export class RedisCacheService implements CacheService {
  private readonly redisClient: redis.RedisClientType;

  constructor() {
    this.redisClient = redis.createClient();
  }

  async connect() {
    console.log("Connecting to Redis ...");

    await this.redisClient.connect();
  }

  async disconnect() {
    if (this.redisClient.isOpen) {
      console.log("Disconnecting from Redis ...");

      await this.redisClient.disconnect();
    }
  }

  async set(key: string, value: string, expiresInMs?: number) {
    try {
      await this.redisClient.set(
        key,
        value,
        expiresInMs
          ? {
              PX: expiresInMs,
            }
          : undefined
      );
    } catch (exc) {
      console.log("Error in Set Cache", exc);
    }
  }

  get(key: string) {
    return this.redisClient.get(key);
  }
}
