import { cpSync, mkdirSync } from 'node:fs';
mkdirSync('dist/public', { recursive: true });
mkdirSync('dist/migrations', { recursive: true });
cpSync('public', 'dist/public', { recursive: true });
cpSync('migrations', 'dist/migrations', { recursive: true });
