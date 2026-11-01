import fs from 'node:fs';
import path from 'node:path';

export function rejectSymlinkComponents(target: string): void {
  const absolute = path.resolve(target);
  let current = path.parse(absolute).root;
  for (const part of absolute.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    try {
      if (fs.lstatSync(current).isSymbolicLink()) throw new Error('Unsafe filesystem path');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw error;
    }
  }
}

export function privateDirectory(directory: string, create = false): string {
  directory = path.resolve(directory);
  rejectSymlinkComponents(directory);
  if (create && !fs.existsSync(directory)) fs.mkdirSync(directory, { mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.uid !== process.getuid?.() || (stat.mode & 0o777) !== 0o700) {
    throw new Error('Data directory must be owned by this user with mode 0700');
  }
  return directory;
}

export function privateFile(filename: string): void {
  rejectSymlinkComponents(filename);
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== process.getuid?.() || (stat.mode & 0o777) !== 0o600) {
    throw new Error('Data file must be owned by this user with mode 0600 and one link');
  }
}

export function createPrivateFile(filename: string, content: string | Buffer): void {
  rejectSymlinkComponents(filename);
  const fd = fs.openSync(filename, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
  try {
    fs.writeFileSync(fd, content);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

export function readPrivateFile(filename: string): Buffer {
  privateFile(filename);
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    if (stat.size > 4096 || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600) throw new Error('Unsafe data file');
    return fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

export function checkDataFiles(directory: string): void {
  privateDirectory(directory);
  for (const entry of fs.readdirSync(directory)) privateFile(path.join(directory, entry));
}
