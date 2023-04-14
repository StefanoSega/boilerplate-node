export interface CacheService {
  connect: () => void;
  disconnect: () => void;
  set: (key: string, value: string, expiresInMs?: number) => void;
  get: (key: string) => string | Promise<string>;
}
