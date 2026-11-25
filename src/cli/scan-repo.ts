/**
 * Pre-Clone GitHub Repository Scanner
 *
 * Audits remote GitHub repositories over the GitHub REST API without cloning
 * or writing repository contents to disk.
 */

import { detectShadowAiInPaths } from '../detection/ide-registry';
import { WorkspaceFinding } from '../detection/workspace-rule-types';
import { HeadlessWorkspaceScanner } from './headless-scanner';

export interface ParsedGithubRepo {
  owner: string;
  repo: string;
  ref?: string;
}

export interface ScanRepoOptions {
  ref?: string;
  token?: string;
  fetchFn?: typeof fetch;
  maxFiles?: number;
  maxBytes?: number;
  scanner?: HeadlessWorkspaceScanner;
}

interface GithubRepoResponse {
  default_branch?: string;
}

interface GithubTreeItem {
  path?: string;
  type?: string;
  size?: number;
}

interface GithubTreeResponse {
  tree?: GithubTreeItem[];
  truncated?: boolean;
}

interface GithubContentsPayload {
  content?: unknown;
  encoding?: unknown;
}

const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_MAX_FILES = 100;
const GITHUB_SEGMENT_RE = /^[A-Za-z0-9._-]+$/;

const RISKY_PATH_PATTERNS: RegExp[] = [
  /(?:^|\/)\.vscode\/(?:settings|tasks|launch|mcp)\.json$/,
  /(?:^|\/)\.devcontainer\/(?:[^/]+\/)?devcontainer\.json$/,
  /(?:^|\/)\.claude\/.+/,
  /(?:^|\/)\.cursor\/.+/,
  /(?:^|\/)\.cursorrules$/,
  /(?:^|\/)\.agents\/.+/,
  /(?:^|\/)\.agent\/.+/,
  /(?:^|\/)\.kiro\/.+/,
  /(?:^|\/)\.codex\/.+/,
  /(?:^|\/)\.trae\/.+/,
  /(?:^|\/)\.qoder\/.+/,
  /(?:^|\/)\.zed\/.+/,
  /(?:^|\/)opencode\.json$/,
  /(?:^|\/)\.opencode\/.+/,
  /(?:^|\/)package\.json$/,
  /(?:^|\/)\.npmrc$/,
  /(?:^|\/)pip\.conf$/,
  /(?:^|\/)\.mcp\.json$/,
  /(?:^|\/)mcp\.json$/,
  /(?:^|\/)mcp_config\.json$/,
  /(?:^|\/)claude\.md$/,
  /(?:^|\/)agents\.md$/,
  /(?:^|\/)agents\.override\.md$/,
  /(?:^|\/)gemini\.md$/,
  /(?:^|\/)skill\.md$/,
  /(?:^|\/)\.windsurfrules$/,
  /(?:^|\/)\.clinerules$/,
  /(?:^|\/)\.github\/copilot-instructions\.md$/,
  /(?:^|\/)\.git\/config$/,
  /(?:^|\/)\.git\/hooks\/.+/,
  /(?:^|\/)\.gitmodules$/,
  /(?:^|\/)\.husky\/.+/,
  /(?:^|\/)\.pre-commit-config\.ya?ml$/,
  /\.ipynb$/,
  /\.csproj$/,
  /\.vcxproj$/,
  /(?:^|\/)directory\.build\.props$/,
  /(?:^|\/)directory\.build\.targets$/,
  /(?:^|\/)project\.pbxproj$/,
  /(?:^|\/)\.dir-locals\.el$/,
  /(?:^|\/)\.vimrc$/,
  /(?:^|\/)\.nvimrc$/,
  /(?:^|\/)\.nvim\.lua$/,
  /(?:^|\/)\.exrc$/,
  /(?:^|\/)lazy-lock\.json$/,
];

function assertValidOwnerAndRepo(owner: string, repo: string, original: string): void {
  if (
    !GITHUB_SEGMENT_RE.test(owner) ||
    !GITHUB_SEGMENT_RE.test(repo) ||
    owner === '.' ||
    owner === '..' ||
    repo === '.' ||
    repo === '..'
  ) {
    throw new Error(`Invalid GitHub owner or repository name in "${original}"`);
  }
}

export function parseGithubRepoUrl(repoUrlOrSlug: string): ParsedGithubRepo {
  const trimmed = repoUrlOrSlug.trim();
  if (!trimmed) {
    throw new Error('GitHub repository URL or owner/repo slug must not be empty');
  }
  if (/[\s\\]/.test(trimmed)) {
    throw new Error(`Invalid characters in GitHub repository target "${repoUrlOrSlug}"`);
  }

  const looksLikeUrl = trimmed.includes('://') || trimmed.startsWith('//') || /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed);

  if (looksLikeUrl) {
    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new Error(`Invalid GitHub repository URL: "${repoUrlOrSlug}"`);
    }

    if (parsed.protocol !== 'https:') {
      throw new Error(`Unsupported protocol "${parsed.protocol}"; only https://github.com URLs are allowed`);
    }
    if (parsed.hostname.toLowerCase() !== 'github.com' || parsed.port !== '') {
      throw new Error(`Unsupported host "${parsed.hostname}"; only github.com is allowed`);
    }
    if (parsed.username !== '' || parsed.password !== '') {
      throw new Error('Credentials in GitHub repository URL are not allowed');
    }
    if (parsed.search !== '') {
      throw new Error('Query parameters in GitHub repository URL are not allowed');
    }

    const schemeEnd = trimmed.indexOf('://') + 3;
    const authorityAndRest = trimmed.slice(schemeEnd);
    const pathStart = authorityAndRest.indexOf('/');
    const rawPathPart = pathStart === -1 ? '' : authorityAndRest.slice(pathStart).split(/[?#]/)[0];
    const hasTraversalSegment = rawPathPart.split('/').some((seg) => {
      const lower = seg.toLowerCase();
      return lower === '.' || lower === '..' || lower === '%2e' || lower === '%2e%2e';
    });
    if (hasTraversalSegment) {
      throw new Error(`Invalid path traversal segment in GitHub URL "${repoUrlOrSlug}"`);
    }

    const segments = parsed.pathname
      .replace(/^\/+|\/+$/g, '')
      .split('/')
      .filter((s) => s.length > 0);

    if (segments.length < 2) {
      throw new Error(`Malformed GitHub repository URL "${repoUrlOrSlug}"; expected https://github.com/owner/repo`);
    }

    const owner = segments[0];
    const rawRepo = segments[1];
    const repo = rawRepo.endsWith('.git') ? rawRepo.slice(0, -4) : rawRepo;

    if (segments.length === 2) {
      assertValidOwnerAndRepo(owner, repo, repoUrlOrSlug);
      return { owner, repo };
    }

    if (segments.length >= 4 && segments[2] === 'tree') {
      if (rawRepo.endsWith('.git')) {
        throw new Error(`Malformed GitHub tree URL "${repoUrlOrSlug}"`);
      }
      const refSegments = segments.slice(3).map((seg) => {
        try {
          return decodeURIComponent(seg);
        } catch {
          throw new Error(`Malformed percent-encoding in ref of "${repoUrlOrSlug}"`);
        }
      });
      if (refSegments.some((seg) => seg.length === 0 || seg === '.' || seg === '..')) {
        throw new Error(`Invalid ref in GitHub URL "${repoUrlOrSlug}"`);
      }
      assertValidOwnerAndRepo(owner, repo, repoUrlOrSlug);
      return { owner, repo, ref: refSegments.join('/') };
    }

    throw new Error(`Unsupported GitHub repository URL path in "${repoUrlOrSlug}"`);
  }

  if (trimmed.includes('@') || trimmed.includes(':')) {
    throw new Error(
      `Unsupported repository format "${repoUrlOrSlug}"; use https://github.com/owner/repo or owner/repo`,
    );
  }

  const parts = trimmed.split('/');
  if (parts.length !== 2) {
    throw new Error(
      `Invalid GitHub repository slug "${repoUrlOrSlug}"; expected "owner/repo" or https://github.com/owner/repo`,
    );
  }

  const owner = parts[0];
  const repo = parts[1].endsWith('.git') ? parts[1].slice(0, -4) : parts[1];
  assertValidOwnerAndRepo(owner, repo, repoUrlOrSlug);
  return { owner, repo };
}

export function isRiskyRepoPath(relPath: string): boolean {
  const norm = relPath
    .replace(/\\/g, '/')
    .replace(/^(?:\.\/)+/, '')
    .replace(/^\/+/, '')
    .toLowerCase();

  if (!norm || norm.endsWith('/')) {
    return false;
  }
  if (/(?:^|\/)\.git\/hooks\/.+\.sample$/.test(norm)) {
    return false;
  }

  return RISKY_PATH_PATTERNS.some((pattern) => pattern.test(norm));
}

async function readResponseTextSafe(res: Response): Promise<string> {
  if (typeof res.text === 'function') {
    return res.text();
  }
  if (typeof res.json === 'function') {
    const payload = await res.json();
    return typeof payload === 'string' ? payload : JSON.stringify(payload);
  }
  return '';
}

async function readResponseJsonSafe<T>(res: Response): Promise<T> {
  if (typeof res.json === 'function') {
    return (await res.json()) as T;
  }
  const text = await readResponseTextSafe(res);
  return JSON.parse(text) as T;
}

async function fetchGithubJson<T>(fetchImpl: typeof fetch, url: string, headers: Record<string, string>): Promise<T> {
  const res = await fetchImpl(url, { headers });
  if (!res.ok) {
    let detail = '';
    try {
      const text = await readResponseTextSafe(res);
      if (text) {
        detail = `: ${text.slice(0, 200)}`;
      }
    } catch {
      // ignore error response body read failures
    }
    throw new Error(`GitHub API request failed (${res.status}) for ${url}${detail}`);
  }
  return readResponseJsonSafe<T>(res);
}

function decodeContentsPayload(payload: GithubContentsPayload): string | null {
  if (typeof payload.content !== 'string') {
    return null;
  }
  if (payload.encoding === 'base64') {
    return Buffer.from(payload.content.replace(/\s+/g, ''), 'base64').toString('utf8');
  }
  if (payload.encoding === 'utf-8' || payload.encoding === 'utf8') {
    return payload.content;
  }
  return null;
}

async function fetchBlobContent(
  fetchImpl: typeof fetch,
  url: string,
  headers: Record<string, string>,
): Promise<string | null> {
  const res = await fetchImpl(url, { headers });
  if (!res.ok) {
    if (res.status === 404) {
      return null;
    }
    throw new Error(`GitHub API request failed (${res.status}) for ${url}`);
  }

  if (typeof res.text === 'function') {
    const rawBody = await res.text();
    try {
      const parsed = JSON.parse(rawBody) as unknown;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        const decoded = decodeContentsPayload(parsed as GithubContentsPayload);
        if (decoded !== null) {
          return decoded;
        }
      }
    } catch {
      // Raw non-JSON file text response
    }
    return rawBody;
  }

  if (typeof res.json === 'function') {
    const parsed = (await res.json()) as unknown;
    if (typeof parsed === 'string') {
      return parsed;
    }
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const decoded = decodeContentsPayload(parsed as GithubContentsPayload);
      if (decoded !== null) {
        return decoded;
      }
      return JSON.stringify(parsed);
    }
  }

  return null;
}

export async function scanRemoteGithubRepo(
  repoUrlOrSlug: string,
  options?: ScanRepoOptions,
): Promise<WorkspaceFinding[]> {
  const parsed = parseGithubRepoUrl(repoUrlOrSlug);
  const fetchImpl = options?.fetchFn ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new Error('Global fetch is unavailable; provide options.fetchFn or run on Node.js >= 18');
  }

  const rawToken =
    options?.token !== undefined ? options.token : process.env.GITHUB_TOKEN?.trim() || process.env.GH_TOKEN?.trim();
  const token = rawToken?.trim();
  const headers: Record<string, string> = { Accept: 'application/vnd.github+json', 'User-Agent': 'open-shepherd-cli' };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const maxBytes = options?.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxFiles = Math.max(0, options?.maxFiles ?? DEFAULT_MAX_FILES);
  const scanner = options?.scanner ?? new HeadlessWorkspaceScanner();

  const ownerSeg = encodeURIComponent(parsed.owner);
  const repoSeg = encodeURIComponent(parsed.repo);

  let ref = options?.ref ?? parsed.ref;
  if (!ref) {
    const repoMeta = await fetchGithubJson<GithubRepoResponse>(
      fetchImpl,
      `https://api.github.com/repos/${ownerSeg}/${repoSeg}`,
      headers,
    );
    if (!repoMeta.default_branch) {
      throw new Error(`Unable to determine default_branch for ${parsed.owner}/${parsed.repo}`);
    }
    ref = repoMeta.default_branch;
  }

  const encodedRef = encodeURIComponent(ref);
  const treeUrl = `https://api.github.com/repos/${ownerSeg}/${repoSeg}/git/trees/${encodedRef}?recursive=1`;
  const treeResp = await fetchGithubJson<GithubTreeResponse>(fetchImpl, treeUrl, headers);

  const blobs = (treeResp.tree ?? []).filter(
    (item): item is { path: string; type: 'blob'; size?: number } =>
      item.type === 'blob' && typeof item.path === 'string' && item.path.length > 0,
  );

  const allBlobPaths = blobs.map((blob) => blob.path);
  const findings: WorkspaceFinding[] = [...detectShadowAiInPaths(allBlobPaths)];

  const targetBlobs = blobs
    .filter((item) => isRiskyRepoPath(item.path) && (item.size ?? 0) <= maxBytes)
    .slice(0, maxFiles);

  for (const item of targetBlobs) {
    const encodedPath = item.path
      .split('/')
      .map((seg) => encodeURIComponent(seg))
      .join('/');
    const contentUrl = `https://api.github.com/repos/${ownerSeg}/${repoSeg}/contents/${encodedPath}?ref=${encodedRef}`;
    const content = await fetchBlobContent(fetchImpl, contentUrl, headers);
    if (content === null || Buffer.byteLength(content, 'utf8') > maxBytes) {
      continue;
    }
    findings.push(...scanner.scanContent(content, item.path));
  }

  return findings;
}
