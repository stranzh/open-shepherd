import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { IDE_AND_AGENT_REGISTRY } from '../detection/ide-registry';

export interface InstalledIdeEntry {
  id: string;
  name: string;
  matchedHomePaths: string[];
}

export interface InstalledExtensionEntry {
  ide: string;
  id: string;
  name: string;
  publisher?: string;
  version?: string;
  path: string;
}

export interface IdeInventoryReport {
  timestamp: string;
  hostname: string;
  homeDir: string;
  ides: InstalledIdeEntry[];
  extensions: InstalledExtensionEntry[];
}

const EXTENSION_DIRS: Array<{ ide: string; relPath: string }> = [
  { ide: 'vscode', relPath: path.join('.vscode', 'extensions') },
  { ide: 'cursor', relPath: path.join('.cursor', 'extensions') },
  { ide: 'vscodium', relPath: path.join('.vscode-oss', 'extensions') },
  { ide: 'windsurf', relPath: path.join('.windsurf', 'extensions') },
  { ide: 'kiro', relPath: path.join('.kiro', 'extensions') },
];

function expandHomePath(homeDir: string, p: string): string {
  if (p.startsWith('~/') || p.startsWith('~\\')) {
    return path.join(homeDir, p.slice(2));
  }
  return p;
}

/**
 * Collects host inventory of installed AI IDEs/agents and their extensions.
 */
export function collectIdeInventory(homeDir: string = os.homedir()): IdeInventoryReport {
  const ides: InstalledIdeEntry[] = [];

  for (const entry of IDE_AND_AGENT_REGISTRY) {
    const matchedHomePaths: string[] = [];
    for (const hp of entry.homePaths) {
      const resolved = expandHomePath(homeDir, hp);
      if (fs.existsSync(resolved)) {
        matchedHomePaths.push(resolved);
      }
    }
    if (matchedHomePaths.length > 0) {
      ides.push({ id: entry.id, name: entry.name, matchedHomePaths });
    }
  }

  const extensions: InstalledExtensionEntry[] = [];
  for (const extDirSpec of EXTENSION_DIRS) {
    const extRoot = path.join(homeDir, extDirSpec.relPath);
    if (!fs.existsSync(extRoot)) {
      continue;
    }

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(extRoot, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const dirent of entries) {
      if (!dirent.isDirectory()) {
        continue;
      }
      const extPath = path.join(extRoot, dirent.name);
      const pkgPath = path.join(extPath, 'package.json');
      if (!fs.existsSync(pkgPath)) {
        continue;
      }
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as {
          name?: unknown;
          publisher?: unknown;
          version?: unknown;
        };
        const name = typeof pkg.name === 'string' ? pkg.name : dirent.name;
        const publisher = typeof pkg.publisher === 'string' ? pkg.publisher : undefined;
        const version = typeof pkg.version === 'string' ? pkg.version : undefined;
        const id = publisher ? `${publisher}.${name}` : name;

        extensions.push({ ide: extDirSpec.ide, id, name, publisher, version, path: extPath });
      } catch {
        // Skip malformed extension package.json
      }
    }
  }

  return { timestamp: new Date().toISOString(), hostname: os.hostname(), homeDir, ides, extensions };
}

/**
 * Formats an IdeInventoryReport as OCSF Inventory Info (class_uid: 5001) JSONL.
 */
export function formatInventoryOcsf(inventory: IdeInventoryReport): string {
  const lines: string[] = [];

  for (const ide of inventory.ides) {
    lines.push(
      JSON.stringify({
        class_uid: 5001,
        category_uid: 5,
        activity_id: 2,
        time: inventory.timestamp,
        device: { hostname: inventory.hostname },
        software: { name: ide.name, uid: ide.id, type: 'ide', install_paths: ide.matchedHomePaths },
      }),
    );
  }

  for (const ext of inventory.extensions) {
    lines.push(
      JSON.stringify({
        class_uid: 5001,
        category_uid: 5,
        activity_id: 2,
        time: inventory.timestamp,
        device: { hostname: inventory.hostname },
        software: {
          name: ext.name,
          uid: ext.id,
          vendor_name: ext.publisher,
          version: ext.version,
          type: 'ide_extension',
          parent_uid: ext.ide,
          install_path: ext.path,
        },
      }),
    );
  }

  return lines.join('\n');
}
