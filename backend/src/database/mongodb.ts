import { logger } from '../utils/logger';

type CollectionStub = {
  insertOne: (...args: any[]) => Promise<never>;
  findOne: (...args: any[]) => Promise<never>;
  findOneAndUpdate: (...args: any[]) => Promise<never>;
  updateOne: (...args: any[]) => Promise<never>;
  countDocuments: (...args: any[]) => Promise<never>;
  deleteOne: (...args: any[]) => Promise<never>;
};

export async function connectMongoDB(): Promise<null> {
  logger.info('MongoDB disabled in simplified SQLite setup');
  return null;
}

export function getMongoDb(): null {
  return null;
}

export async function closeMongoDB(): Promise<void> {
  logger.info('MongoDB compatibility layer closed');
}

// Collection access helpers
export function getCollection(collectionName: string): CollectionStub {
  throw new Error(`MongoDB collection "${collectionName}" is unavailable in simplified SQLite setup`);
}
