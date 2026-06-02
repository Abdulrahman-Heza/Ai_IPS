import { getAllRows, runQuery } from './sqlite';
import { logger } from '../utils/logger';

export interface QueryResult<T = any> {
  rows: T[];
  rowCount: number;
}

function toSqliteQuery(text: string): string {
  return text
    .replace(/\$(\d+)/g, '?')
    .replace(/NOW\(\)/gi, 'CURRENT_TIMESTAMP')
    .replace(/\btrue\b/gi, '1')
    .replace(/\bfalse\b/gi, '0');
}

export async function connectPostgres(): Promise<null> {
  logger.info('PostgreSQL compatibility layer using SQLite');
  return null;
}

export function getPostgresPool(): null {
  return null;
}

export async function query<T = any>(
  text: string,
  params: any[] = []
): Promise<QueryResult<T>> {
  const sql = toSqliteQuery(text);
  const returnsRows = /^\s*select/i.test(sql) || /\breturning\b/i.test(sql);

  if (returnsRows) {
    const rows = await getAllRows(sql, params);
    return {
      rows: rows as T[],
      rowCount: rows.length,
    };
  }

  await runQuery(sql, params);
  return {
    rows: [],
    rowCount: 1,
  };
}

export async function closePostgres(): Promise<void> {
  logger.info('SQLite compatibility layer closed');
}
