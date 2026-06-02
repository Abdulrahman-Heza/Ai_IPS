import { logger } from '../utils/logger';

class InMemoryRedisClient {
  private values = new Map<string, string>();
  private lists = new Map<string, string[]>();
  isOpen = true;

  async incr(key: string): Promise<number> {
    const next = parseInt(this.values.get(key) || '0', 10) + 1;
    this.values.set(key, next.toString());
    return next;
  }

  async get(key: string): Promise<string | null> {
    return this.values.get(key) || null;
  }

  async set(key: string, value: string): Promise<void> {
    this.values.set(key, value);
  }

  async setEx(key: string, _ttl: number, value: string): Promise<void> {
    this.values.set(key, value);
  }

  async lpush(key: string, value: string): Promise<void> {
    const list = this.lists.get(key) || [];
    list.unshift(value);
    this.lists.set(key, list);
  }

  async lrange(key: string, start: number, stop: number): Promise<string[]> {
    const list = this.lists.get(key) || [];
    const end = stop === -1 ? undefined : stop + 1;
    return list.slice(start, end);
  }

  async expire(_key: string, _seconds: number): Promise<void> {
    // Expiration is ignored for this simplified local cache.
  }

  async del(key: string): Promise<void> {
    this.values.delete(key);
    this.lists.delete(key);
  }

  async flushDb(): Promise<void> {
    this.values.clear();
    this.lists.clear();
  }

  async quit(): Promise<void> {
    this.isOpen = false;
  }
}

export const redisClient = new InMemoryRedisClient();

export async function connectRedis(): Promise<InMemoryRedisClient> {
  logger.info('Redis compatibility layer using in-memory cache');
  return redisClient;
}

export function getRedis(): InMemoryRedisClient {
  return redisClient;
}

export async function closeRedis(): Promise<void> {
  await redisClient.quit();
  logger.info('In-memory Redis compatibility layer closed');
}

export async function setCache(key: string, value: any, ttl?: number): Promise<void> {
  const serialized = JSON.stringify(value);
  if (ttl) await redisClient.setEx(key, ttl, serialized);
  else await redisClient.set(key, serialized);
}

export async function getCache<T = any>(key: string): Promise<T | null> {
  const value = await redisClient.get(key);
  return value ? JSON.parse(value) : null;
}

export async function deleteCache(key: string): Promise<void> {
  await redisClient.del(key);
}

export async function flushCache(): Promise<void> {
  await redisClient.flushDb();
}
