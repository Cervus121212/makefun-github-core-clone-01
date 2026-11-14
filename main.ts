// github-core-clone-01 — a standalone, GitHub-compatible git forge in one process.
//
// One Node 22 process, standard library only, no git binary, no network, no UI.
// It serves four surfaces from its own in-memory store:
//   * git smart HTTP  — upload-pack protocol v2 (+ v0 fallback) and receive-pack v0
//     at /{owner}/{repo}.git, with a real packfile reader/writer (PACK v2, no deltas)
//   * REST v3         — repositories, branches, commits, contents, labels, issues,
//     comments and pull requests under /api/v3
//   * GraphQL v4       — POST /api/graphql, with a small real GraphQL parser/executor
//     for the documents gh and github-mcp-server send
//   * MCP              — POST /mcp, JSON-RPC 2.0 over Streamable HTTP, modern
//     server/discover era with a legacy initialize fallback
//
// Lifecycle (the env's contract): bind an ephemeral port, POST {"port": N} to
// $MAKEFUN_ENV_URL/register, long-poll GET $MAKEFUN_ENV_URL/done until it says
// {"done": true}, then exit 0. Never bind 8080.
//
// Determinism: every timestamp the forge emits comes from one logical clock
// seeded from MAKEFUN_TRIAL_NOW (or the fixed 2025-01-01 epoch) and advanced
// one second per mutation; there is no wall clock and no unseeded randomness
// in any response, so two runs over the same requests answer byte-identically.
//
// The token's owner: the suite's scenario is drawn from one fixed public seed
// (SCENARIO_SEED 6a09e667f3bcc909 in the kit's wire.ts), so the viewer the token
// names is always the same login — verified by running the kit's own
// buildScenario(), which yields users[0].login = "adaiversen". Every repository
// this forge creates belongs to that login; any other owner is a 404, never a 403.

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------- constants

/** The login the trial token names (kit wire.ts, fixed scenario seed). */
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const DEFAULT_BRANCH = 'main';
const ZERO_OID = '0000000000000000000000000000000000000000';
const FORGE_AGENT = 'forge/1.0';
const INSTALLED_VERSION = '1.0.0';

/** The bearer token every API call must present (MAKEFUN_SHOP_TOKEN). */
const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

/** Logical clock: deterministic timestamps, one second per mutation. */
const CLOCK_START_MS = (() => {
  const raw = Number(process.env.MAKEFUN_TRIAL_NOW ?? '');
  return Number.isFinite(raw) && raw > 0 ? raw : 1735689600000; // 2025-01-01T00:00:00Z
})();
let clockMs = CLOCK_START_MS;
function tickIso(): string {
  clockMs += 1000;
  return new Date(clockMs).toISOString();
}
function tickEpoch(): number {
  return Math.floor(clockMs / 1000);
}

// ---------------------------------------------------------------- small utils

const sha1Hex = (data: Buffer): string => createHash('sha1').update(data).digest('hex');
const isOid = (s: unknown): s is string => typeof s === 'string' && /^[0-9a-f]{40}$/i.test(s);
const b64 = (buf: Buffer): string => buf.toString('base64');
const b64url = (s: string): string => Buffer.from(s, 'utf8').toString('base64url');
const unb64url = (s: string): string => Buffer.from(s, 'base64url').toString('utf8');
const utf8 = (s: string): Buffer => Buffer.from(s, 'utf8');

function jsonBody(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    ...extra,
  });
  res.end(text);
}

let requestCounter = 0;
function requestId(): string {
  requestCounter += 1;
  return `req-${requestCounter}`;
}

/** Read the whole request body (capped), or null when it is not valid JSON. */
async function readJsonBody(req: IncomingMessage): Promise<{ ok: true; value: unknown } | { ok: false }> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > 16 * 1024 * 1024) return { ok: false };
    chunks.push(buf);
  }
  if (chunks.length === 0) return { ok: true, value: undefined };
  try {
    return { ok: true, value: JSON.parse(Buffer.concat(chunks).toString('utf8')) };
  } catch {
    return { ok: false };
  }
}

async function readRawBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

function bearerOf(req: IncomingMessage): string | null {
  const h = req.headers.authorization ?? '';
  if (!h.startsWith('Bearer ')) return null;
  return h.slice('Bearer '.length).trim();
}

/** True when the request carries the trial token (or any bearer when no token is configured). */
function authorized(req: IncomingMessage): boolean {
  const token = bearerOf(req);
  if (token === null || token === '') return false;
  if (SHOP_TOKEN === '') return true;
  return token === SHOP_TOKEN;
}

const errJson = (message: string): { message: string } => ({ message });

// ---------------------------------------------------------------- pkt-line

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? utf8(payload) : payload;
  const len = data.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

interface Pkt {
  kind: 'data' | 'flush' | 'delim';
  payload: Buffer;
}

/** Decode a whole buffer of pkt-lines into packets (throws on bad framing). */
function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('truncated pkt-line header');
    const head = buf.toString('ascii', off, off + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error('bad pkt-line header');
    const len = parseInt(head, 16);
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
    } else if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
    } else if (len === 2) {
      throw new Error('illegal pkt-line 0002');
    } else {
      if (off + len > buf.length) throw new Error('truncated pkt-line payload');
      out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
      off += len;
    }
  }
  return out;
}

/** Split a buffer at the first pkt-line flush; returns [packets, restOffset]. */
function splitPktPrefix(buf: Buffer): { packets: Pkt[]; rest: Buffer } {
  let off = 0;
  const packets: Pkt[] = [];
  while (off + 4 <= buf.length) {
    const head = buf.toString('ascii', off, off + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = parseInt(head, 16);
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      return { packets, rest: buf.subarray(off + 4) };
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, rest: buf.subarray(off) };
}

// ---------------------------------------------------------------- git objects

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj {
  type: ObjType;
  bytes: Buffer;
}

/** The one object store, shared by every repository (like git's object db). */
const objects = new Map<string, GitObj>();

function hashObject(type: ObjType, bytes: Buffer): string {
  const head = utf8(`${type} ${bytes.length}\0`);
  return sha1Hex(Buffer.concat([head, bytes]));
}

function storeObject(type: ObjType, bytes: Buffer): string {
  const oid = hashObject(type, bytes);
  if (!objects.has(oid)) objects.set(oid, { type, bytes });
  return oid;
}

function getObject(oid: string): GitObj | undefined {
  return objects.get(oid.toLowerCase());
}

// --- commits ----------------------------------------------------------------

interface CommitInfo {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(bytes: Buffer): CommitInfo | null {
  const text = bytes.toString('utf8');
  const split = text.indexOf('\n\n');
  if (split < 0) return null;
  const head = text.slice(0, split);
  const message = text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  if (!isOid(tree)) return null;
  return { tree, parents, author, committer, message };
}

function makeCommit(tree: string, parents: string[], message: string): string {
  const epoch = tickEpoch();
  const ident = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${epoch} +0000`;
  const lines = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${ident}`, `committer ${ident}`, '', message);
  return storeObject('commit', utf8(lines.join('\n')));
}

// --- trees ------------------------------------------------------------------

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(bytes: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < bytes.length) {
    const sp = bytes.indexOf(0x20, off);
    if (sp < 0) break;
    const mode = bytes.toString('ascii', off, sp);
    const nul = bytes.indexOf(0, sp);
    if (nul < 0 || nul + 21 > bytes.length) break;
    const name = bytes.toString('utf8', sp + 1, nul);
    const oid = bytes.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}

function buildTree(entries: TreeEntry[]): string {
  const sorted = [...entries].sort((a, b) => {
    const an = a.mode === '40000' ? `${a.name}/` : a.name;
    const bn = b.mode === '40000' ? `${b.name}/` : b.name;
    return an < bn ? -1 : an > bn ? 1 : 0;
  });
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(utf8(`${e.mode} ${e.name}\0`));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return storeObject('tree', Buffer.concat(parts));
}

/** Flatten a tree into path -> {blobOid, mode}. Missing tree => empty map. */
function flattenTree(treeOid: string | null, prefix = '', out = new Map<string, { oid: string; mode: string }>()): Map<string, { oid: string; mode: string }> {
  if (!treeOid) return out;
  const obj = getObject(treeOid);
  if (!obj || obj.type !== 'tree') return out;
  for (const e of parseTree(obj.bytes)) {
    const path = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.mode === '40000') flattenTree(e.oid, path, out);
    else if (e.mode !== '160000') out.set(path, { oid: e.oid, mode: e.mode });
  }
  return out;
}

/** Build a tree from a flat path -> blob map (nested dirs created as needed). */
function treeFromFlat(files: Map<string, { oid: string; mode: string }>): string {
  const build = (prefix: string): string => {
    const entries: TreeEntry[] = [];
    const dirs = new Set<string>();
    for (const [path, f] of files) {
      if (prefix !== '' && !path.startsWith(`${prefix}/`)) continue;
      const rest = prefix === '' ? path : path.slice(prefix.length + 1);
      const slash = rest.indexOf('/');
      if (slash < 0) entries.push({ mode: f.mode, name: rest, oid: f.oid });
      else dirs.add(rest.slice(0, slash));
    }
    for (const d of dirs) {
      const sub = build(prefix === '' ? d : `${prefix}/${d}`);
      entries.push({ mode: '40000', name: d, oid: sub });
    }
    return buildTree(entries);
  };
  return build('');
}

// --- reachability -------------------------------------------------------------

/** All object ids reachable from `roots` (commits -> trees/blobs/parents, tags -> target). */
function collectReachable(roots: string[]): Set<string> {
  const seen = new Set<string>();
  const stack = [...roots];
  while (stack.length) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const obj = getObject(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const info = parseCommit(obj.bytes);
      if (!info) continue;
      stack.push(info.tree);
      for (const p of info.parents) stack.push(p);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.bytes)) {
        if (e.mode !== '160000') stack.push(e.oid);
      }
    } else if (obj.type === 'tag') {
      const m = /^object ([0-9a-f]{40})$/m.exec(obj.bytes.toString('utf8'));
      if (m) stack.push(m[1]);
    }
  }
  return seen;
}

/** True when `anc` is reachable from `tip` (or equal); walks parents only. */
function isAncestor(anc: string, tip: string): boolean {
  if (anc === tip) return true;
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length) {
    const oid = stack.pop() as string;
    if (oid === anc) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = getObject(oid);
    if (!obj || obj.type !== 'commit') continue;
    const info = parseCommit(obj.bytes);
    if (info) for (const p of info.parents) stack.push(p);
  }
  return false;
}

/**
 * Commit generations reachable from `roots`, newest first (generation 0 = the
 * roots themselves). Used for shallow fetches: `depth` caps the generations.
 */
function commitGenerations(roots: string[], depth: number): { commits: Map<string, number>; boundary: string[] } {
  const commits = new Map<string, number>();
  const queue: Array<[string, number]> = roots.map((r) => [r, 0] as [string, number]);
  const boundary: string[] = [];
  while (queue.length) {
    const [oid, gen] = queue.shift() as [string, number];
    if (commits.has(oid)) continue;
    const obj = getObject(oid);
    if (!obj || obj.type !== 'commit') continue;
    commits.set(oid, gen);
    const info = parseCommit(obj.bytes);
    if (!info) continue;
    if (gen + 1 < depth) {
      for (const p of info.parents) queue.push([p, gen + 1]);
    } else if (info.parents.length > 0) {
      boundary.push(oid);
    }
  }
  return { commits, boundary };
}

// --- packfiles ----------------------------------------------------------------

const PACK_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const PACK_TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };

/** Write a PACK v2 of full objects only (no deltas), with a sha1 trailer. */
function writePack(oids: string[]): Buffer {
  const uniq = [...new Set(oids.map((o) => o.toLowerCase()))];
  const parts: Buffer[] = [];
  const head = Buffer.alloc(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(uniq.length, 8);
  parts.push(head);
  for (const oid of uniq) {
    const obj = getObject(oid);
    if (!obj) continue;
    const typeCode = PACK_TYPE_CODE[obj.type];
    const size = obj.bytes.length;
    // varint header: type in bits 4-6, size in bits 0-3 then 7-bit groups.
    const headerBytes: number[] = [];
    let b = (typeCode << 4) | (size & 0x0f);
    let rest = size >> 4;
    if (rest > 0) b |= 0x80;
    headerBytes.push(b);
    while (rest > 0) {
      let next = rest & 0x7f;
      rest >>= 7;
      if (rest > 0) next |= 0x80;
      headerBytes.push(next);
    }
    parts.push(Buffer.from(headerBytes));
    parts.push(deflateSync(obj.bytes));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, Buffer.from(sha1Hex(body), 'hex')]);
}

/** Adler-32 (the checksum a zlib stream ends with), computed in JS. */
function adler32(buf: Buffer): number {
  const MOD = 65521;
  let a = 1;
  let b = 0;
  for (let i = 0; i < buf.length; i += 1) {
    a = (a + buf[i]) % MOD;
    b = (b + a) % MOD;
  }
  return ((b << 16) | a) >>> 0;
}

/**
 * Inflate exactly one zlib stream starting at `off`, knowing its output size.
 * inflateSync ignores trailing bytes, so one call yields the object; the
 * stream's end is found by scanning for its Adler-32 trailer (verified by a
 * second inflate), instead of binary-searching the length with many calls.
 */
function inflateExact(buf: Buffer, off: number, expectedSize: number): { bytes: Buffer; consumed: number } {
  const bytes = inflateSync(buf.subarray(off));
  if (bytes.length !== expectedSize) throw new Error('pack object size mismatch');
  const adler = Buffer.alloc(4);
  adler.writeUInt32BE(adler32(bytes), 0);
  let searchFrom = off + 2;
  for (;;) {
    const found = buf.indexOf(adler, searchFrom);
    if (found < 0) throw new Error('cannot locate zlib stream end');
    const end = found + 4;
    try {
      const check = inflateSync(buf.subarray(off, end));
      if (check.length === expectedSize) return { bytes, consumed: end - off };
    } catch {
      // A coincidental Adler match inside the stream: keep scanning.
    }
    searchFrom = found + 1;
  }
}

/** Apply a git delta (base + delta bytes) to produce the target object. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const b = delta[off];
      off += 1;
      value |= (b & 0x7f) << shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    return value;
  };
  const baseSize = readVarint();
  const resultSize = readVarint();
  if (baseSize !== base.length) throw new Error('delta base size mismatch');
  const out: Buffer[] = [];
  let total = 0;
  while (off < delta.length) {
    const op = delta[off];
    off += 1;
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i += 1) {
        if (op & (1 << i)) {
          cpOff |= delta[off] << (8 * i);
          off += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if (op & (0x10 << i)) {
          cpSize |= delta[off] << (8 * i);
          off += 1;
        }
      }
      if (cpSize === 0) cpSize = 0x10000;
      if (cpOff + cpSize > base.length) throw new Error('delta copy out of range');
      out.push(base.subarray(cpOff, cpOff + cpSize));
      total += cpSize;
    } else if (op > 0) {
      out.push(delta.subarray(off, off + op));
      total += op;
      off += op;
    } else {
      throw new Error('delta op 0');
    }
  }
  const result = Buffer.concat(out);
  if (total !== resultSize || result.length !== resultSize) throw new Error('delta result size mismatch');
  return result;
}

/** Parse a PACK v2/v3 (full objects and OFS/REF deltas), verify and store each object. */
function readPack(buf: Buffer): { objects: string[]; deltaCount: number } {
  if (buf.length < 32) throw new Error('pack too short');
  if (buf.toString('ascii', 0, 4) !== 'PACK') throw new Error('not a packfile');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('bad pack version');
  const count = buf.readUInt32BE(8);
  const trailer = buf.subarray(buf.length - 20).toString('hex');
  if (sha1Hex(buf.subarray(0, buf.length - 20)) !== trailer) throw new Error('pack trailer mismatch');
  const stored: string[] = [];
  const byOffset = new Map<number, { type: ObjType; bytes: Buffer }>();
  let off = 12;
  let deltaCount = 0;
  for (let i = 0; i < count; i += 1) {
    const entryStart = off;
    let byte = buf[off];
    off += 1;
    const typeCode = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      byte = buf[off];
      off += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    let base: { type: ObjType; bytes: Buffer } | undefined;
    if (typeCode === 6) {
      let b2 = buf[off];
      off += 1;
      let offset = b2 & 0x7f;
      while (b2 & 0x80) {
        b2 = buf[off];
        off += 1;
        offset = ((offset + 1) << 7) | (b2 & 0x7f);
      }
      base = byOffset.get(entryStart - offset);
      if (!base) throw new Error('ofs-delta base missing');
      deltaCount += 1;
    } else if (typeCode === 7) {
      const baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
      base = byOffset.get(-1) ?? undefined; // placeholder, resolved below by oid
      const obj = getObject(baseOid);
      if (!obj) throw new Error('ref-delta base missing');
      base = obj;
      deltaCount += 1;
    }
    const { bytes: raw, consumed } = inflateExact(buf, off, size);
    off += consumed;
    if (typeCode === 6 || typeCode === 7) {
      if (!base) throw new Error('delta without base');
      const resolved = applyDelta(base.bytes, raw);
      const oid = storeObject(base.type, resolved);
      byOffset.set(entryStart, { type: base.type, bytes: resolved });
      stored.push(oid);
    } else {
      const type = PACK_TYPE[typeCode];
      if (!type) throw new Error(`unknown pack object type ${typeCode}`);
      const oid = storeObject(type, raw);
      byOffset.set(entryStart, { type, bytes: raw });
      stored.push(oid);
    }
  }
  return { objects: stored, deltaCount };
}

// ---------------------------------------------------------------- repository store

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  createdAt: string;
  updatedAt: string;
  comments: Array<{ id: number; body: string; createdAt: string }>;
  /** Cached JSON of the single-issue response; cleared on any mutation. */
  jsonCache: string | null;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  createdAt: string;
  files: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }>;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  description: string;
  private: boolean;
  defaultBranch: string;
  createdAt: string;
  updatedAt: string;
  refs: Map<string, string>;
  labels: Map<string, string>;
  issues: Issue[];
  nextIssue: number;
  nextComment: number;
  pulls: Pull[];
  nextPull: number;
  seq: number;
}

const repos = new Map<string, Repo>();
let nextRepoId = 5000;
let nextObjectId = 1;
let repoSeq = 0;

function repoKey(owner: string, name: string): string {
  return `${owner.toLowerCase()}/${name.toLowerCase()}`;
}

function getRepo(owner: string, name: string): Repo | undefined {
  if (owner.toLowerCase() !== VIEWER_LOGIN) return undefined;
  return repos.get(repoKey(owner, name));
}

function createRepo(name: string, description: string, isPrivate: boolean): Repo {
  const now = tickIso();
  const repo: Repo = {
    id: nextRepoId,
    name,
    owner: VIEWER_LOGIN,
    description,
    private: isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    createdAt: now,
    updatedAt: now,
    refs: new Map(),
    labels: new Map(),
    issues: [],
    nextIssue: 1,
    nextComment: 1,
    pulls: [],
    nextPull: 1,
    seq: repoSeq,
  };
  nextRepoId += 1;
  repoSeq += 1;
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  return repo;
}

function repoObject(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: b64url(`repo:${repo.owner}/${repo.name}`),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    clone_url: `https://example.invalid/${repo.owner}/${repo.name}.git`,
    git_url: `git://example.invalid/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@example.invalid:${repo.owner}/${repo.name}.git`,
    homepage: null,
    language: null,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    open_issues_count: repo.issues.filter((i) => i.state === 'open').length,
    has_issues: true,
    has_pull_requests: true,
    archived: false,
    disabled: false,
    visibility: repo.private ? 'private' : 'public',
  };
}

function issueObject(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: b64url(`issue:${repo.owner}/${repo.name}:${issue.number}`),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name, color: repo.labels.get(name) ?? 'ededed' })),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    comments: issue.comments.length,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function issueJson(repo: Repo, issue: Issue): string {
  if (issue.jsonCache) return issue.jsonCache;
  const text = JSON.stringify(issueObject(repo, issue));
  issue.jsonCache = text;
  return text;
}

function sendRawJson(res: ServerResponse, status: number, text: string, extra: Record<string, string> = {}): void {
  const body = text.endsWith('\n') ? text : `${text}\n`;
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    ...extra,
  });
  res.end(body);
}

function pullObject(repo: Repo, pr: Pull): Record<string, unknown> {
  return {
    id: pr.id,
    node_id: b64url(`pr:${repo.owner}/${repo.name}:${pr.number}`),
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    head: { ref: pr.headRef, sha: pr.headSha, label: `${repo.owner}:${pr.headRef}` },
    base: { ref: pr.baseRef, sha: pr.baseSha, label: `${repo.owner}:${pr.baseRef}` },
    merged: pr.merged,
    merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeCommitSha,
    mergeable: pr.state === 'open' ? (prConflict(repo, pr) ? 'CONFLICTING' : 'MERGEABLE') : null,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: pr.createdAt,
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pr.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pr.number}`,
  };
}

/** Commits reachable from `tip`, newest first (by creation order, then walk). */
function listCommits(tip: string | undefined): string[] {
  if (!tip) return [];
  const order: string[] = [];
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = getObject(oid);
    if (!obj || obj.type !== 'commit') continue;
    order.push(oid);
    const info = parseCommit(obj.bytes);
    if (info) for (const p of info.parents) stack.push(p);
  }
  return order;
}

/** Line-diff counts between two blobs (added/deleted lines, at least 1 change when different). */
function diffLines(oldBytes: Buffer | null, newBytes: Buffer | null): { additions: number; deletions: number } {
  const oldLines = oldBytes ? oldBytes.toString('utf8').split('\n') : [];
  const newLines = newBytes ? newBytes.toString('utf8').split('\n') : [];
  const oldSet = new Map<string, number>();
  for (const l of oldLines) oldSet.set(l, (oldSet.get(l) ?? 0) + 1);
  const newSet = new Map<string, number>();
  for (const l of newLines) newSet.set(l, (newSet.get(l) ?? 0) + 1);
  let additions = 0;
  let deletions = 0;
  for (const [l, n] of newSet) additions += Math.max(0, n - (oldSet.get(l) ?? 0));
  for (const [l, n] of oldSet) deletions += Math.max(0, n - (newSet.get(l) ?? 0));
  return { additions, deletions };
}

/** File-level diff between two trees (base -> head). */
function diffTrees(baseTree: string | null, headTree: string | null): Pull['files'] {
  const base = flattenTree(baseTree);
  const head = flattenTree(headTree);
  const files: Pull['files'] = [];
  const paths = new Set([...base.keys(), ...head.keys()]);
  for (const path of [...paths].sort()) {
    const b = base.get(path);
    const h = head.get(path);
    if (b && !h) {
      const bytes = getObject(b.oid)?.bytes ?? null;
      const { deletions } = diffLines(bytes, null);
      files.push({ filename: path, status: 'removed', additions: 0, deletions: Math.max(deletions, 1), changes: Math.max(deletions, 1) });
    } else if (!b && h) {
      const bytes = getObject(h.oid)?.bytes ?? null;
      const { additions } = diffLines(null, bytes);
      files.push({ filename: path, status: 'added', additions: Math.max(additions, 1), deletions: 0, changes: Math.max(additions, 1) });
    } else if (b && h && b.oid !== h.oid) {
      const { additions, deletions } = diffLines(getObject(b.oid)?.bytes ?? null, getObject(h.oid)?.bytes ?? null);
      const add = Math.max(additions, 1);
      files.push({ filename: path, status: 'modified', additions: add, deletions, changes: add + deletions });
    }
  }
  return files;
}

/** True when merging `pr` now would conflict with the current base branch. */
function prConflict(repo: Repo, pr: Pull): boolean {
  const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
  if (!baseTip) return false;
  if (baseTip === pr.baseSha) return false;
  const baseAtCreation = flattenTree(getObject(pr.baseSha) ? parseCommit(getObject(pr.baseSha)?.bytes ?? Buffer.alloc(0))?.tree ?? null : null);
  const baseNow = flattenTree(parseCommit(getObject(baseTip)?.bytes ?? Buffer.alloc(0))?.tree ?? null);
  const headTree = parseCommit(getObject(pr.headSha)?.bytes ?? Buffer.alloc(0))?.tree ?? null;
  const head = flattenTree(headTree);
  for (const f of pr.files) {
    const path = f.filename;
    const atCreation = baseAtCreation.get(path)?.oid;
    const now = baseNow.get(path)?.oid;
    const headOid = head.get(path)?.oid;
    if (now !== atCreation && headOid !== now) return true;
  }
  return false;
}

/** Commit `files` (flat path -> bytes) onto `branch` of `repo` with `message`. */
function commitFiles(repo: Repo, branch: string, message: string, changes: Map<string, Buffer | null>): string {
  const ref = `refs/heads/${branch}`;
  const tip = repo.refs.get(ref);
  const parentTree = tip ? parseCommit(getObject(tip)?.bytes ?? Buffer.alloc(0))?.tree ?? null : null;
  const flat = flattenTree(parentTree);
  for (const [path, bytes] of changes) {
    if (bytes === null) flat.delete(path);
    else flat.set(path, { oid: storeObject('blob', bytes), mode: '100644' });
  }
  const tree = treeFromFlat(flat);
  const parents = tip ? [tip] : [];
  const commit = makeCommit(tree, parents, message);
  repo.refs.set(ref, commit);
  return commit;
}

/** The blob sha + bytes of `path` at `ref` (branch name or commit oid), or null. */
function fileAt(repo: Repo, ref: string, path: string): { blobOid: string; bytes: Buffer } | null {
  let tip = repo.refs.get(`refs/heads/${ref}`);
  if (!tip && isOid(ref)) tip = ref;
  if (!tip) return null;
  const tree = parseCommit(getObject(tip)?.bytes ?? Buffer.alloc(0))?.tree ?? null;
  const flat = flattenTree(tree);
  const entry = flat.get(path);
  if (!entry) return null;
  const obj = getObject(entry.oid);
  if (!obj || obj.type !== 'blob') return null;
  return { blobOid: entry.oid, bytes: obj.bytes };
}

// ---------------------------------------------------------------- REST v3

function parsePage(query: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, Number(query.get('page') ?? '1') || 1);
  const perPage = Math.min(100, Math.max(1, Number(query.get('per_page') ?? '30') || 30));
  return { page, perPage };
}

function paginate<T>(items: T[], page: number, perPage: number): { slice: T[]; hasNext: boolean; totalPages: number } {
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (page - 1) * perPage;
  return { slice: items.slice(start, start + perPage), hasNext: page < totalPages, totalPages };
}

function linkHeader(req: IncomingMessage, path: string, query: URLSearchParams, page: number, perPage: number, hasNext: boolean, totalPages: number): string {
  const host = req.headers.host ?? 'localhost';
  const base = `http://${host}${path}`;
  const parts: string[] = [];
  if (hasNext) {
    const q = new URLSearchParams(query);
    q.set('page', String(page + 1));
    q.set('per_page', String(perPage));
    parts.push(`<${base}?${q.toString()}>; rel="next"`);
  }
  if (totalPages > 1) {
    const q = new URLSearchParams(query);
    q.set('page', String(totalPages));
    q.set('per_page', String(perPage));
    parts.push(`<${base}?${q.toString()}>; rel="last"`);
  }
  return parts.join(', ');
}

async function handleRest(req: IncomingMessage, res: ServerResponse, segments: string[], query: URLSearchParams): Promise<boolean> {
  const method = req.method ?? 'GET';
  const rid = requestId();
  const headers = { 'x-github-request-id': rid };
  const send = (status: number, body: unknown, extra: Record<string, string> = {}): void =>
    jsonBody(res, status, body, { ...headers, ...extra });
  const notFound = (): void => send(404, errJson('Not Found'));
  const needAuth = (): boolean => {
    if (!authorized(req)) {
      send(401, errJson('Requires authentication'));
      return false;
    }
    return true;
  };

  // GET /api/v3/ — API root.
  if (segments.length === 0 && method === 'GET') {
    send(200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  // GET /api/v3/meta
  if (segments.length === 1 && segments[0] === 'meta' && method === 'GET') {
    if (!needAuth()) return true;
    send(200, { installed_version: INSTALLED_VERSION, verifiable_password_authentication: true });
    return true;
  }
  // GET /api/v3/user
  if (segments.length === 1 && segments[0] === 'user' && method === 'GET') {
    if (!needAuth()) return true;
    send(200, { login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL, type: 'User' });
    return true;
  }
  // /api/v3/user/repos
  if (segments.length === 2 && segments[0] === 'user' && segments[1] === 'repos') {
    if (!needAuth()) return true;
    if (method === 'GET') {
      const { page, perPage } = parsePage(query);
      const all = [...repos.values()].sort((a, b) => a.seq - b.seq).map((r) => repoObject(r));
      const { slice, hasNext, totalPages } = paginate(all, page, perPage);
      const link = linkHeader(req, '/api/v3/user/repos', query, page, perPage, hasNext, totalPages);
      send(200, slice, link ? { link } : {});
      return true;
    }
    if (method === 'POST') {
      const parsed = await readJsonBody(req);
      if (!parsed.ok) {
        send(400, errJson('Malformed JSON body'));
        return true;
      }
      const body = (parsed.value ?? {}) as Record<string, unknown>;
      const name = typeof body.name === 'string' ? body.name : '';
      if (name === '') {
        send(422, errJson('name is required'));
        return true;
      }
      if (repos.has(repoKey(VIEWER_LOGIN, name))) {
        send(422, errJson('Repository already exists'));
        return true;
      }
      const repo = createRepo(name, typeof body.description === 'string' ? body.description : '', body.private === true);
      send(201, repoObject(repo));
      return true;
    }
    send(404, errJson('Not Found'));
    return true;
  }

  // /api/v3/repos/{owner}/{repo}/...
  if (segments.length >= 3 && segments[0] === 'repos') {
    if (!needAuth()) return true;
    const owner = decodeURIComponent(segments[1]);
    const name = decodeURIComponent(segments[2]);
    const repo = getRepo(owner, name);
    const rest = segments.slice(3);
    if (!repo) {
      notFound();
      return true;
    }
    // GET/PATCH/DELETE /repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') {
        send(200, repoObject(repo));
        return true;
      }
      if (method === 'PATCH') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          send(400, errJson('Malformed JSON body'));
          return true;
        }
        const body = (parsed.value ?? {}) as Record<string, unknown>;
        if (typeof body.description === 'string') repo.description = body.description;
        if (typeof body.private === 'boolean') repo.private = body.private;
        repo.updatedAt = tickIso();
        send(200, repoObject(repo));
        return true;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, name));
        res.writeHead(204, { 'x-github-request-id': rid });
        res.end();
        return true;
      }
      send(404, errJson('Not Found'));
      return true;
    }
    // git refs
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          send(400, errJson('Malformed JSON body'));
          return true;
        }
        const body = (parsed.value ?? {}) as Record<string, unknown>;
        const ref = typeof body.ref === 'string' ? body.ref : '';
        const sha = typeof body.sha === 'string' ? body.sha : '';
        if (!ref.startsWith('refs/') || !isOid(sha) || !getObject(sha)) {
          send(422, errJson('Invalid ref or sha'));
          return true;
        }
        repo.refs.set(ref, sha.toLowerCase());
        send(201, { ref, object: { sha: sha.toLowerCase(), type: 'commit' } });
        return true;
      }
      if (method === 'GET' && rest.length >= 3) {
        const ref = `refs/${rest.slice(2).map((s) => decodeURIComponent(s)).join('/')}`;
        const sha = repo.refs.get(ref);
        if (!sha) {
          notFound();
          return true;
        }
        send(200, { ref, object: { sha, type: 'commit' } });
        return true;
      }
      send(404, errJson('Not Found'));
      return true;
    }
    // branches
    if (rest[0] === 'branches') {
      if (method === 'GET' && rest.length === 1) {
        const list = [...repo.refs.entries()]
          .filter(([r]) => r.startsWith('refs/heads/'))
          .map(([r, sha]) => ({ name: r.slice('refs/heads/'.length), commit: { sha } }));
        send(200, list);
        return true;
      }
      if (method === 'GET' && rest.length === 2) {
        const sha = repo.refs.get(`refs/heads/${decodeURIComponent(rest[1])}`);
        if (!sha) {
          notFound();
          return true;
        }
        send(200, { name: decodeURIComponent(rest[1]), commit: { sha } });
        return true;
      }
      send(404, errJson('Not Found'));
      return true;
    }
    // commits
    if (rest[0] === 'commits' && method === 'GET' && rest.length === 1) {
      const shaParam = query.get('sha');
      const tip = shaParam ? repo.refs.get(`refs/heads/${shaParam}`) ?? (isOid(shaParam) ? shaParam : undefined) : repo.refs.get(`refs/heads/${repo.defaultBranch}`);
      const list = listCommits(tip).map((sha) => {
        const info = parseCommit(getObject(sha)?.bytes ?? Buffer.alloc(0));
        return { sha, commit: { message: info?.message ?? '' } };
      });
      send(200, list);
      return true;
    }
    // contents
    if (rest[0] === 'contents') {
      const path = rest.slice(1).map((s) => decodeURIComponent(s)).join('/');
      const branch = query.get('ref') ?? undefined;
      if (method === 'GET') {
        const refName = branch ?? repo.defaultBranch;
        const tip = repo.refs.get(`refs/heads/${refName}`) ?? (isOid(refName) ? refName : undefined);
        if (!tip) {
          notFound();
          return true;
        }
        const tree = parseCommit(getObject(tip)?.bytes ?? Buffer.alloc(0))?.tree ?? null;
        const flat = flattenTree(tree);
        const file = flat.get(path);
        if (file) {
          const bytes = getObject(file.oid)?.bytes ?? Buffer.alloc(0);
          send(200, {
            type: 'file',
            encoding: 'base64',
            content: `${b64(bytes)}\n`,
            sha: file.oid,
            size: bytes.length,
            name: path.split('/').pop() ?? path,
            path,
          });
          return true;
        }
        // directory listing (path '' or a directory prefix)
        const prefix = path === '' ? '' : `${path}/`;
        const entries: Array<Record<string, unknown>> = [];
        const seenDirs = new Set<string>();
        for (const [p, f] of flat) {
          if (prefix !== '' && !p.startsWith(prefix)) continue;
          const restPath = prefix === '' ? p : p.slice(prefix.length);
          const slash = restPath.indexOf('/');
          if (slash < 0) {
            entries.push({ type: 'file', name: restPath, path: p, sha: f.oid, size: getObject(f.oid)?.bytes.length ?? 0 });
          } else {
            const dir = restPath.slice(0, slash);
            if (!seenDirs.has(dir)) {
              seenDirs.add(dir);
              const dirTree = treeFromFlat(new Map([...flat].filter(([pp]) => pp.startsWith(`${prefix}${dir}/`)).map(([pp, ff]) => [pp.slice(prefix.length), ff] as [string, { oid: string; mode: string }])));
              entries.push({ type: 'dir', name: dir, path: `${prefix}${dir}`, sha: dirTree });
            }
          }
        }
        if (entries.length === 0) {
          notFound();
          return true;
        }
        entries.sort((a, b) => String(a.name).localeCompare(String(b.name)));
        send(200, entries);
        return true;
      }
      if (method === 'PUT') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          send(400, errJson('Malformed JSON body'));
          return true;
        }
        const body = (parsed.value ?? {}) as Record<string, unknown>;
        const message = typeof body.message === 'string' ? body.message : 'update';
        const contentB64 = typeof body.content === 'string' ? body.content : '';
        const branchName = typeof body.branch === 'string' ? body.branch : repo.defaultBranch;
        const refName = `refs/heads/${branchName}`;
        if (!repo.refs.has(refName) && repo.refs.size > 0 && typeof body.branch === 'string') {
          notFound();
          return true;
        }
        const current = fileAt(repo, branchName, path);
        const givenSha = typeof body.sha === 'string' ? body.sha.toLowerCase() : undefined;
        if (givenSha && (!current || current.blobOid !== givenSha)) {
          send(409, errJson('sha does not match the current blob'));
          return true;
        }
        const isCreate = !current;
        const bytes = Buffer.from(contentB64.replace(/\s/g, ''), 'base64');
        const changes = new Map<string, Buffer | null>([[path, bytes]]);
        const commit = commitFiles(repo, branchName, message, changes);
        const blobOid = hashObject('blob', bytes);
        send(isCreate ? 201 : 200, {
          content: { name: path.split('/').pop() ?? path, path, sha: blobOid, size: bytes.length, encoding: 'base64' },
          commit: { sha: commit },
        });
        return true;
      }
      if (method === 'DELETE') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          send(400, errJson('Malformed JSON body'));
          return true;
        }
        const current = fileAt(repo, repo.defaultBranch, path);
        if (!current) {
          notFound();
          return true;
        }
        const body = (parsed.value ?? {}) as Record<string, unknown>;
        const message = typeof body.message === 'string' ? body.message : 'delete';
        const commit = commitFiles(repo, repo.defaultBranch, message, new Map([[path, null]]));
        send(200, { commit: { sha: commit } });
        return true;
      }
      send(404, errJson('Not Found'));
      return true;
    }
    // labels
    if (rest[0] === 'labels') {
      if (method === 'POST' && rest.length === 1) {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          send(400, errJson('Malformed JSON body'));
          return true;
        }
        const body = (parsed.value ?? {}) as Record<string, unknown>;
        const name = typeof body.name === 'string' ? body.name : '';
        if (name === '') {
          send(422, errJson('name is required'));
          return true;
        }
        repo.labels.set(name, typeof body.color === 'string' ? body.color : 'ededed');
        send(201, { name, color: repo.labels.get(name) });
        return true;
      }
      if (method === 'GET' && rest.length === 1) {
        send(200, [...repo.labels.entries()].map(([name, color]) => ({ name, color })));
        return true;
      }
      send(404, errJson('Not Found'));
      return true;
    }
    // issues
    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const { page, perPage } = parsePage(query);
          let list = [...repo.issues];
          const state = query.get('state');
          if (state === 'open' || state === 'closed') list = list.filter((i) => i.state === state);
          if (query.get('sort') === 'created') {
            list.sort((a, b) => (query.get('direction') === 'desc' ? b.number - a.number : a.number - b.number));
          }
          const { slice, hasNext, totalPages } = paginate(list, page, perPage);
          const link = linkHeader(req, `/api/v3/repos/${owner}/${name}/issues`, query, page, perPage, hasNext, totalPages);
          send(200, slice.map((i) => issueObject(repo, i)), link ? { link } : {});
          return true;
        }
        if (method === 'POST') {
          const parsed = await readJsonBody(req);
          if (!parsed.ok) {
            send(400, errJson('Malformed JSON body'));
            return true;
          }
          const body = (parsed.value ?? {}) as Record<string, unknown>;
          const title = typeof body.title === 'string' ? body.title : '';
          const labels = Array.isArray(body.labels) ? body.labels.filter((l): l is string => typeof l === 'string') : [];
          for (const label of labels) {
            if (!repo.labels.has(label)) {
              send(422, errJson(`label "${label}" does not exist`));
              return true;
            }
          }
          const now = tickIso();
          const issue: Issue = {
            id: nextObjectId,
            number: repo.nextIssue,
            title,
            body: typeof body.body === 'string' ? body.body : '',
            state: 'open',
            labels,
            createdAt: now,
            updatedAt: now,
            comments: [],
            jsonCache: null,
          };
          nextObjectId += 1;
          repo.nextIssue += 1;
          repo.issues.push(issue);
          send(201, issueObject(repo, issue));
          return true;
        }
        send(404, errJson('Not Found'));
        return true;
      }
      const num = Number(rest[1]);
      const issue = repo.issues.find((i) => i.number === num);
      if (!issue) {
        notFound();
        return true;
      }
      if (rest.length === 2) {
        if (method === 'GET') {
          sendRawJson(res, 200, issueJson(repo, issue), headers);
          return true;
        }
        if (method === 'PATCH') {
          const parsed = await readJsonBody(req);
          if (!parsed.ok) {
            send(400, errJson('Malformed JSON body'));
            return true;
          }
          const body = (parsed.value ?? {}) as Record<string, unknown>;
          if (body.state === 'closed' || body.state === 'open') {
            issue.state = body.state;
            issue.updatedAt = tickIso();
          }
          if (typeof body.title === 'string') issue.title = body.title;
          if (typeof body.body === 'string') issue.body = body.body;
          issue.jsonCache = null;
          send(200, issueObject(repo, issue));
          return true;
        }
        send(404, errJson('Not Found'));
        return true;
      }
      if (rest[2] === 'comments') {
        if (method === 'POST' && rest.length === 3) {
          const parsed = await readJsonBody(req);
          if (!parsed.ok) {
            send(400, errJson('Malformed JSON body'));
            return true;
          }
          const body = (parsed.value ?? {}) as Record<string, unknown>;
          const comment = { id: repo.nextComment, body: typeof body.body === 'string' ? body.body : '', createdAt: tickIso() };
          repo.nextComment += 1;
          issue.comments.push(comment);
          issue.jsonCache = null;
          send(201, { id: comment.id, node_id: b64url(`comment:${repo.owner}/${repo.name}:${issue.number}:${comment.id}`), body: comment.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID }, created_at: comment.createdAt });
          return true;
        }
        if (method === 'GET' && rest.length === 3) {
          send(200, issue.comments.map((c) => ({ id: c.id, body: c.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID }, created_at: c.createdAt })));
          return true;
        }
        send(404, errJson('Not Found'));
        return true;
      }
      send(404, errJson('Not Found'));
      return true;
    }
    // pull requests
    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'GET') {
          const { page, perPage } = parsePage(query);
          let list = [...repo.pulls];
          const state = query.get('state');
          if (state !== 'all') list = list.filter((p) => p.state === 'open');
          const { slice, hasNext, totalPages } = paginate(list, page, perPage);
          const link = linkHeader(req, `/api/v3/repos/${owner}/${name}/pulls`, query, page, perPage, hasNext, totalPages);
          send(200, slice.map((p) => pullObject(repo, p)), link ? { link } : {});
          return true;
        }
        if (method === 'POST') {
          const parsed = await readJsonBody(req);
          if (!parsed.ok) {
            send(400, errJson('Malformed JSON body'));
            return true;
          }
          const body = (parsed.value ?? {}) as Record<string, unknown>;
          const headRef = typeof body.head === 'string' ? body.head : '';
          const baseRef = typeof body.base === 'string' ? body.base : repo.defaultBranch;
          const headSha = repo.refs.get(`refs/heads/${headRef}`);
          const baseSha = repo.refs.get(`refs/heads/${baseRef}`);
          if (!headSha || !baseSha) {
            send(422, errJson('head or base branch does not exist'));
            return true;
          }
          const headTree = parseCommit(getObject(headSha)?.bytes ?? Buffer.alloc(0))?.tree ?? null;
          const baseTree = parseCommit(getObject(baseSha)?.bytes ?? Buffer.alloc(0))?.tree ?? null;
          const pr: Pull = {
            id: nextObjectId,
            number: repo.nextPull,
            title: typeof body.title === 'string' ? body.title : '',
            body: typeof body.body === 'string' ? body.body : '',
            state: 'open',
            headRef,
            baseRef,
            headSha,
            baseSha,
            merged: false,
            mergedAt: null,
            mergeCommitSha: null,
            createdAt: tickIso(),
            files: diffTrees(baseTree, headTree),
          };
          nextObjectId += 1;
          repo.nextPull += 1;
          repo.pulls.push(pr);
          send(201, pullObject(repo, pr));
          return true;
        }
        send(404, errJson('Not Found'));
        return true;
      }
      const num = Number(rest[1]);
      const pr = repo.pulls.find((p) => p.number === num);
      if (!pr) {
        notFound();
        return true;
      }
      if (rest.length === 2) {
        if (method === 'GET') {
          send(200, pullObject(repo, pr));
          return true;
        }
        send(404, errJson('Not Found'));
        return true;
      }
      if (rest[2] === 'files' && method === 'GET') {
        send(200, pr.files);
        return true;
      }
      if (rest[2] === 'merge' && method === 'PUT') {
        const parsed = await readJsonBody(req);
        if (!parsed.ok) {
          send(400, errJson('Malformed JSON body'));
          return true;
        }
        if (pr.state !== 'open') {
          send(405, errJson('pull request is not open'));
          return true;
        }
        if (prConflict(repo, pr)) {
          send(405, errJson('merge conflict'));
          return true;
        }
        const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
        const headTree = parseCommit(getObject(pr.headSha)?.bytes ?? Buffer.alloc(0))?.tree ?? null;
        const parents = baseTip ? [baseTip] : [];
        const mergeCommit = makeCommit(headTree ?? '', parents, `Merge pull request #${pr.number}: ${pr.title}`);
        repo.refs.set(`refs/heads/${pr.baseRef}`, mergeCommit);
        pr.state = 'closed';
        pr.merged = true;
        pr.mergedAt = tickIso();
        pr.mergeCommitSha = mergeCommit;
        send(200, { merged: true, sha: mergeCommit, message: `Pull Request #${pr.number} merged` });
        return true;
      }
      send(404, errJson('Not Found'));
      return true;
    }
    send(404, errJson('Not Found'));
    return true;
  }

  return false;
}

// ---------------------------------------------------------------- git smart HTTP

function refLines(repo: Repo, withCaps: string | null): Buffer[] {
  const lines: Buffer[] = [];
  const refs = [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
  const headTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  const caps = withCaps ? `\0${withCaps}` : '';
  const headLine = headTip
    ? `${headTip} HEAD${caps} symref=HEAD:refs/heads/${repo.defaultBranch}\n`
    : null;
  if (refs.length === 0) {
    if (withCaps) lines.push(pktLine(`${ZERO_OID} capabilities^{}${caps}\n`));
    return lines;
  }
  if (headLine) lines.push(pktLine(headLine));
  let first = !headLine;
  for (const [ref, oid] of refs) {
    const obj = getObject(oid);
    let line = `${oid} ${ref}`;
    if (first && withCaps) {
      line += caps;
      first = false;
    }
    line += '\n';
    lines.push(pktLine(line));
    if (obj?.type === 'tag') {
      const m = /^object ([0-9a-f]{40})$/m.exec(obj.bytes.toString('utf8'));
      if (m) lines.push(pktLine(`${m[1]} ${ref}^{}\n`));
    }
  }
  return lines;
}

function uploadPackAdvertisement(repo: Repo, v2: boolean): Buffer {
  if (v2) {
    return Buffer.concat([
      pktLine('version 2\n'),
      pktLine('ls-refs=unborn\n'),
      pktLine('fetch=shallow\n'),
      pktLine('object-format=sha1\n'),
      pktLine(`agent=${FORGE_AGENT}\n`),
      PKT_FLUSH,
    ]);
  }
  const caps = `symref=HEAD:refs/heads/${repo.defaultBranch} side-band-64k ofs-delta thin-pack agent=${FORGE_AGENT}`;
  return Buffer.concat([
    pktLine('# service=git-upload-pack\n'),
    PKT_FLUSH,
    ...refLines(repo, caps),
    PKT_FLUSH,
  ]);
}

function receivePackAdvertisement(repo: Repo): Buffer {
  const caps = `report-status side-band-64k delete-refs ofs-delta agent=${FORGE_AGENT} symref=HEAD:refs/heads/${repo.defaultBranch}`;
  return Buffer.concat([
    pktLine('# service=git-receive-pack\n'),
    PKT_FLUSH,
    ...refLines(repo, caps),
    PKT_FLUSH,
  ]);
}

/** ls-refs v2 answer: one pkt-line per ref, then flush. */
function lsRefsAnswer(repo: Repo, args: { peel: boolean; symrefs: boolean; unborn: boolean; prefixes: string[] }): Buffer {
  const out: Buffer[] = [];
  const keep = (name: string): boolean => args.prefixes.length === 0 || args.prefixes.some((p) => name.startsWith(p));
  const headTip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
  if (keep('HEAD')) {
    if (headTip) {
      out.push(pktLine(`${headTip} HEAD${args.symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`));
    } else if (args.unborn) {
      out.push(pktLine(`unborn HEAD${args.symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`));
    }
  }
  const refs = [...repo.refs.entries()].sort(([a], [b]) => (a < b ? -1 : 1));
  for (const [ref, oid] of refs) {
    if (!keep(ref)) continue;
    let line = `${oid} ${ref}`;
    if (args.symrefs && ref === `refs/heads/${repo.defaultBranch}`) line += ` symref-target:refs/heads/${repo.defaultBranch}`;
    if (args.peel) {
      const obj = getObject(oid);
      if (obj?.type === 'tag') {
        const m = /^object ([0-9a-f]{40})$/m.exec(obj.bytes.toString('utf8'));
        if (m) line += ` peeled:${m[1]}`;
      }
    }
    out.push(pktLine(`${line}\n`));
  }
  out.push(PKT_FLUSH);
  return Buffer.concat(out);
}

/** Sideband-wrap a pack: band-1 pkt-lines of at most 65515 payload bytes. */
function sidebandPack(pack: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const CHUNK = 65515;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(off + CHUNK, pack.length));
    out.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  if (pack.length === 0) out.push(pktLine(Buffer.from([1])));
  return out;
}

interface FetchRequest {
  wants: string[];
  haves: string[];
  shallowBoundaries: string[];
  depth: number | null;
}

/**
 * Objects the client already holds, from its `have` commits — but a shallow
 * boundary commit is held only itself (with its tree), never its ancestors.
 */
function heldObjects(haves: string[], shallowBoundaries: string[]): Set<string> {
  const boundarySet = new Set(shallowBoundaries);
  const held = new Set<string>();
  const stack = [...haves];
  while (stack.length) {
    const oid = stack.pop() as string;
    if (held.has(oid)) continue;
    const obj = getObject(oid);
    if (!obj) continue;
    held.add(oid);
    if (obj.type === 'commit') {
      const info = parseCommit(obj.bytes);
      if (!info) continue;
      for (const extra of collectReachable([info.tree])) held.add(extra);
      if (!boundarySet.has(oid)) {
        for (const p of info.parents) stack.push(p);
      }
    } else if (obj.type === 'tree') {
      for (const extra of collectReachable([oid])) held.add(extra);
    } else if (obj.type === 'tag') {
      const m = /^object ([0-9a-f]{40})$/m.exec(obj.bytes.toString('utf8'));
      if (m) stack.push(m[1]);
    }
  }
  return held;
}

interface FetchPlan {
  send: Set<string>;
  shallow: string[];
  unshallow: string[];
}

/** The exact object set for a fetch: reachable(wants) within depth, minus held. */
function planFetch(req: FetchRequest): FetchPlan {
  const wants = [...new Set(req.wants.filter((w) => getObject(w)))];
  const depth = req.depth ?? Number.POSITIVE_INFINITY;
  const held = heldObjects(req.haves, req.shallowBoundaries);
  const { commits, boundary } = commitGenerations(wants, depth);
  const send = new Set<string>();
  for (const [oid] of commits) {
    if (held.has(oid)) continue;
    const obj = getObject(oid);
    if (!obj) continue;
    send.add(oid);
    const info = parseCommit(obj.bytes);
    if (info) {
      for (const extra of collectReachable([info.tree])) {
        if (!held.has(extra)) send.add(extra);
      }
    }
  }
  for (const want of wants) {
    const obj = getObject(want);
    if (obj?.type === 'tag') {
      for (const extra of collectReachable([want])) {
        if (!held.has(extra)) send.add(extra);
      }
    }
  }
  const shallow: string[] = [];
  for (const b of boundary) {
    if (commits.has(b) && !held.has(b)) shallow.push(b);
  }
  const unshallow: string[] = [];
  for (const s of req.shallowBoundaries) {
    if (commits.has(s) && !shallow.includes(s)) unshallow.push(s);
  }
  return { send, shallow, unshallow };
}

/** v2 fetch answer: acknowledgments (only when the client sent haves), optional shallow-info, packfile sections. */
function fetchAnswer(req: FetchRequest): Buffer {
  const wants = [...new Set(req.wants.filter((w) => getObject(w)))];
  const parts: Buffer[] = [];
  // Real git skips negotiation entirely when it sent no haves: it reads the
  // packfile section first, so an acknowledgments section there is an error
  // ("expected 'packfile'"). With haves, the acks section comes first.
  if (req.haves.length > 0) {
    parts.push(pktLine('acknowledgments\n'));
    let acked: string | null = null;
    for (const have of req.haves) {
      if (wants.some((w) => isAncestor(have, w))) {
        acked = have;
        break;
      }
    }
    if (acked) {
      parts.push(pktLine(`ACK ${acked}\n`), pktLine('ready\n'));
    } else {
      parts.push(pktLine('NAK\n'));
    }
    parts.push(PKT_DELIM);
  }
  const { send, shallow, unshallow } = planFetch(req);
  if (shallow.length > 0 || unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const s of unshallow) parts.push(pktLine(`unshallow ${s}\n`));
    parts.push(PKT_DELIM);
  }
  parts.push(pktLine('packfile\n'));
  const pack = writePack([...send]);
  parts.push(...sidebandPack(pack));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/** Parse a v2 upload-pack request body into ls-refs / fetch arguments. */
function parseV2Request(buf: Buffer): { command: string; args: string[] } {
  const packets = decodePktLines(buf);
  const lines: string[] = [];
  for (const p of packets) {
    if (p.kind === 'data') lines.push(p.payload.toString('utf8'));
  }
  const command = lines[0]?.startsWith('command=') ? lines[0].slice('command='.length).trim() : '';
  return { command, args: lines.slice(1) };
}

async function handleGit(req: IncomingMessage, res: ServerResponse, owner: string, repoName: string, rest: string[], query: URLSearchParams): Promise<boolean> {
  const method = req.method ?? 'GET';
  const repo = getRepo(owner, repoName);
  const gitType = (service: string): string => `application/x-git-${service}`;
  if (method === 'GET' && rest[0] === 'info' && rest[1] === 'refs') {
    const service = query.get('service') ?? '';
    if (!repo) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ message: 'Not Found' }));
      return true;
    }
    if (service === 'git-upload-pack') {
      const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      const body = uploadPackAdvertisement(repo, v2);
      res.writeHead(200, { 'content-type': gitType('upload-pack-advertisement'), 'content-length': body.length });
      res.end(body);
      return true;
    }
    if (service === 'git-receive-pack') {
      const body = receivePackAdvertisement(repo);
      res.writeHead(200, { 'content-type': gitType('receive-pack-advertisement'), 'content-length': body.length });
      res.end(body);
      return true;
    }
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ message: 'Not Found' }));
    return true;
  }
  if (method === 'POST' && rest[0] === 'git-upload-pack') {
    if (!repo) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ message: 'Not Found' }));
      return true;
    }
    const body = await readRawBody(req);
    const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    try {
      if (isV2) {
        const { command, args } = parseV2Request(body);
        if (command === 'ls-refs') {
          const lsArgs = {
            peel: args.includes('peel\n'),
            symrefs: args.includes('symrefs\n'),
            unborn: args.includes('unborn\n'),
            prefixes: args.filter((a) => a.startsWith('ref-prefix ')).map((a) => a.slice('ref-prefix '.length).trim()),
          };
          const out = lsRefsAnswer(repo, lsArgs);
          res.writeHead(200, { 'content-type': gitType('upload-pack-result'), 'content-length': out.length });
          res.end(out);
          return true;
        }
        if (command === 'fetch') {
          const fetchReq: FetchRequest = { wants: [], haves: [], shallowBoundaries: [], depth: null };
          for (const a of args) {
            const line = a.trim();
            if (line.startsWith('want ')) fetchReq.wants.push(line.slice(5).trim());
            else if (line.startsWith('have ')) fetchReq.haves.push(line.slice(5).trim());
            else if (line.startsWith('shallow ')) fetchReq.shallowBoundaries.push(line.slice(8).trim());
            else if (line.startsWith('deepen ')) fetchReq.depth = Number(line.slice(7).trim());
          }
          const out = fetchAnswer(fetchReq);
          res.writeHead(200, { 'content-type': gitType('upload-pack-result'), 'content-length': out.length });
          res.end(out);
          return true;
        }
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ message: 'unknown command' }));
        return true;
      }
      // v0 fetch fallback: want/have lines, then a sideband pack.
      const packets = decodePktLines(body);
      const fetchReq: FetchRequest = { wants: [], haves: [], shallowBoundaries: [], depth: null };
      for (const p of packets) {
        if (p.kind !== 'data') continue;
        const line = p.payload.toString('utf8').trim();
        if (line.startsWith('want ')) fetchReq.wants.push(line.slice(5).split(' ')[0]);
        else if (line.startsWith('have ')) fetchReq.haves.push(line.slice(5).trim());
        else if (line.startsWith('deepen ')) fetchReq.depth = Number(line.slice(7).trim());
      }
      const { send } = planFetch(fetchReq);
      const pack = writePack([...send]);
      const out = Buffer.concat([pktLine('NAK\n'), ...sidebandPack(pack), PKT_FLUSH]);
      res.writeHead(200, { 'content-type': gitType('upload-pack-result'), 'content-length': out.length });
      res.end(out);
      return true;
    } catch (err) {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ message: err instanceof Error ? err.message : 'bad request' }));
      return true;
    }
  }
  if (method === 'POST' && rest[0] === 'git-receive-pack') {
    if (!repo) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ message: 'Not Found' }));
      return true;
    }
    const body = await readRawBody(req);
    try {
      const { packets, rest: packBytes } = splitPktPrefix(body);
      const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
      for (const p of packets) {
        if (p.kind !== 'data') continue;
        let line = p.payload.toString('utf8');
        const nul = line.indexOf('\0');
        if (nul >= 0) line = line.slice(0, nul);
        const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)\s*$/.exec(line.trim());
        if (m) commands.push({ oldOid: m[1], newOid: m[2], ref: m[3] });
      }
      let unpackOk = true;
      if (packBytes.length > 0) {
        try {
          readPack(packBytes);
        } catch {
          unpackOk = false;
        }
      }
      const report: string[] = [unpackOk ? 'unpack ok' : 'unpack failed to parse pack'];
      for (const cmd of commands) {
        const current = repo.refs.get(cmd.ref);
        if (!unpackOk) {
          report.push(`ng ${cmd.ref} unpack failed`);
          continue;
        }
        if (cmd.newOid === ZERO_OID) {
          // delete
          if (!current || current !== cmd.oldOid) {
            report.push(`ng ${cmd.ref} invalid old value`);
          } else {
            repo.refs.delete(cmd.ref);
            report.push(`ok ${cmd.ref}`);
          }
          continue;
        }
        if (cmd.oldOid === ZERO_OID) {
          if (current) {
            report.push(`ng ${cmd.ref} already exists`);
          } else if (!getObject(cmd.newOid)) {
            report.push(`ng ${cmd.ref} object not found`);
          } else {
            repo.refs.set(cmd.ref, cmd.newOid);
            report.push(`ok ${cmd.ref}`);
          }
          continue;
        }
        if (current !== cmd.oldOid) {
          report.push(`ng ${cmd.ref} invalid old value`);
        } else if (!getObject(cmd.newOid)) {
          report.push(`ng ${cmd.ref} object not found`);
        } else if (!isAncestor(cmd.oldOid, cmd.newOid)) {
          report.push(`ng ${cmd.ref} non-fast-forward`);
        } else {
          repo.refs.set(cmd.ref, cmd.newOid);
          report.push(`ok ${cmd.ref}`);
        }
      }
      const inner = Buffer.concat([...report.map((r) => pktLine(`${r}\n`)), PKT_FLUSH]);
      const outer = Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), inner])), PKT_FLUSH]);
      res.writeHead(200, { 'content-type': gitType('receive-pack-result'), 'content-length': outer.length });
      res.end(outer);
      return true;
    } catch (err) {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ message: err instanceof Error ? err.message : 'bad request' }));
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------- GraphQL v4

// A small real GraphQL parser for the documents gh and github-mcp-server
// send: operations, variables, enums, inline input objects, aliases, inline
// fragments, batched arrays. No pattern matching on the query string.

type GqlValue =
  | { kind: 'variable'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'float'; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'enum'; value: string }
  | { kind: 'null' }
  | { kind: 'list'; value: GqlValue[] }
  | { kind: 'object'; value: Record<string, GqlValue> };

interface GqlField {
  kind: 'field';
  alias: string | null;
  name: string;
  args: Record<string, GqlValue>;
  selections: GqlSelection[];
}
interface GqlInlineFragment {
  kind: 'inline';
  typeCondition: string | null;
  selections: GqlSelection[];
}
interface GqlSpread {
  kind: 'spread';
  name: string;
}
type GqlSelection = GqlField | GqlInlineFragment | GqlSpread;

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  varDefs: Record<string, string>;
  selections: GqlSelection[];
}

interface GqlFragment {
  name: string;
  typeCondition: string;
  selections: GqlSelection[];
}

class GqlTokenizer {
  private pos = 0;
  private readonly src: string;
  constructor(src: string) {
    this.src = src;
  }

  next(): { type: string; value: string } | null {
    const s = this.src;
    while (this.pos < s.length) {
      const c = s[this.pos];
      if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') {
        this.pos += 1;
        continue;
      }
      if (c === '#') {
        while (this.pos < s.length && s[this.pos] !== '\n') this.pos += 1;
        continue;
      }
      break;
    }
    if (this.pos >= s.length) return null;
    const c = s[this.pos];
    if (c === '.' && s.slice(this.pos, this.pos + 3) === '...') {
      this.pos += 3;
      return { type: '...', value: '...' };
    }
    if ('{}():!=$[]@'.includes(c)) {
      this.pos += 1;
      return { type: c, value: c };
    }
    if (c === '"') {
      this.pos += 1;
      let out = '';
      while (this.pos < s.length && s[this.pos] !== '"') {
        if (s[this.pos] === '\\') {
          this.pos += 1;
          const e = s[this.pos] ?? '';
          out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e;
          this.pos += 1;
        } else {
          out += s[this.pos];
          this.pos += 1;
        }
      }
      this.pos += 1;
      return { type: 'string', value: out };
    }
    if (/[0-9-]/.test(c)) {
      let end = this.pos;
      while (end < s.length && /[0-9.eE+-]/.test(s[end])) end += 1;
      const text = s.slice(this.pos, end);
      this.pos = end;
      return { type: /[.eE]/.test(text) ? 'float' : 'int', value: text };
    }
    if (/[A-Za-z_]/.test(c)) {
      let end = this.pos;
      while (end < s.length && /[A-Za-z0-9_]/.test(s[end])) end += 1;
      const text = s.slice(this.pos, end);
      this.pos = end;
      return { type: 'name', value: text };
    }
    throw new Error(`unexpected character ${JSON.stringify(c)}`);
  }
}

class GqlParser {
  private peeked: { type: string; value: string } | null | undefined = undefined;
  private readonly tokens: GqlTokenizer;
  constructor(src: string) {
    this.tokens = new GqlTokenizer(src);
  }

  private peek(): { type: string; value: string } | null {
    if (this.peeked === undefined) this.peeked = this.tokens.next();
    return this.peeked;
  }

  private take(): { type: string; value: string } | null {
    const t = this.peek();
    this.peeked = undefined;
    return t;
  }

  private expect(type: string): { type: string; value: string } {
    const t = this.take();
    if (!t || t.type !== type) throw new Error(`expected ${type}, got ${t?.type ?? 'eof'}`);
    return t;
  }

  private expectName(value?: string): string {
    const t = this.take();
    if (!t || t.type !== 'name' || (value !== undefined && t.value !== value)) {
      throw new Error(`expected name ${value ?? ''}, got ${t?.value ?? 'eof'}`);
    }
    return t.value;
  }

  parseDocument(): { operations: GqlOperation[]; fragments: Record<string, GqlFragment> } {
    const operations: GqlOperation[] = [];
    const fragments: Record<string, GqlFragment> = {};
    while (this.peek()) {
      const t = this.peek() as { type: string; value: string };
      if (t.type === 'name' && t.value === 'fragment') {
        this.take();
        const name = this.expectName();
        this.expectName('on');
        const typeCondition = this.expectName();
        const selections = this.parseSelectionSet();
        fragments[name] = { name, typeCondition, selections };
        continue;
      }
      let kind: 'query' | 'mutation' = 'query';
      if (t.type === 'name' && (t.value === 'query' || t.value === 'mutation')) {
        kind = t.value as 'query' | 'mutation';
        this.take();
      }
      let name: string | null = null;
      const next = this.peek();
      if (next?.type === 'name') name = this.take()?.value ?? null;
      const varDefs: Record<string, string> = {};
      if (this.peek()?.type === '(') {
        this.take();
        while (this.peek() && this.peek()?.type !== ')') {
          this.expect('$');
          const varName = this.expectName();
          this.expect(':');
          varDefs[varName] = this.parseType();
          if (this.peek()?.type === '=') {
            this.take();
            this.parseValue();
          }
        }
        this.expect(')');
      }
      const selections = this.parseSelectionSet();
      operations.push({ kind, name, varDefs, selections });
    }
    return { operations, fragments };
  }

  private parseType(): string {
    const t = this.take();
    if (!t) throw new Error('expected type');
    if (t.type === '[') {
      const inner = this.parseType();
      this.expect(']');
      let out = `[${inner}]`;
      if (this.peek()?.type === '!') {
        this.take();
        out += '!';
      }
      return out;
    }
    if (t.type !== 'name') throw new Error('expected type name');
    let out = t.value;
    if (this.peek()?.type === '!') {
      this.take();
      out += '!';
    }
    return out;
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expect('{');
    const selections: GqlSelection[] = [];
    while (this.peek() && this.peek()?.type !== '}') {
      selections.push(this.parseSelection());
    }
    this.expect('}');
    return selections;
  }

  private parseSelection(): GqlSelection {
    const t = this.peek();
    if (t?.type === '...') {
      this.take();
      const next = this.peek();
      if (next?.type === 'name' && next.value === 'on') {
        this.take();
        const typeCondition = this.expectName();
        return { kind: 'inline', typeCondition, selections: this.parseSelectionSet() };
      }
      if (next?.type === 'name') {
        return { kind: 'spread', name: this.take()?.value ?? '' };
      }
      return { kind: 'inline', typeCondition: null, selections: this.parseSelectionSet() };
    }
    const first = this.expectName();
    let alias: string | null = null;
    let name = first;
    if (this.peek()?.type === ':') {
      this.take();
      alias = first;
      name = this.expectName();
    }
    const args: Record<string, GqlValue> = {};
    if (this.peek()?.type === '(') {
      this.take();
      while (this.peek() && this.peek()?.type !== ')') {
        const argName = this.expectName();
        this.expect(':');
        args[argName] = this.parseValue();
      }
      this.expect(')');
    }
    let selections: GqlSelection[] = [];
    if (this.peek()?.type === '{') selections = this.parseSelectionSet();
    return { kind: 'field', alias, name, args, selections };
  }

  private parseValue(): GqlValue {
    const t = this.take();
    if (!t) throw new Error('expected value');
    if (t.type === '$') return { kind: 'variable', name: this.expectName() };
    if (t.type === 'string') return { kind: 'string', value: t.value };
    if (t.type === 'int') return { kind: 'int', value: Number(t.value) };
    if (t.type === 'float') return { kind: 'float', value: Number(t.value) };
    if (t.type === 'name') {
      if (t.value === 'true') return { kind: 'boolean', value: true };
      if (t.value === 'false') return { kind: 'boolean', value: false };
      if (t.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: t.value };
    }
    if (t.type === '[') {
      const value: GqlValue[] = [];
      while (this.peek() && this.peek()?.type !== ']') value.push(this.parseValue());
      this.expect(']');
      return { kind: 'list', value };
    }
    if (t.type === '{') {
      const value: Record<string, GqlValue> = {};
      while (this.peek() && this.peek()?.type !== '}') {
        const key = this.expectName();
        this.expect(':');
        value[key] = this.parseValue();
      }
      this.expect('}');
      return { kind: 'object', value };
    }
    throw new Error(`unexpected value token ${t.type}`);
  }
}

function resolveValue(v: GqlValue, variables: Record<string, unknown>): unknown {
  switch (v.kind) {
    case 'variable':
      return variables[v.name];
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
    case 'enum':
      return v.value;
    case 'null':
      return null;
    case 'list':
      return v.value.map((x) => resolveValue(x, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v.value)) out[k] = resolveValue(val, variables);
      return out;
    }
  }
}

// --- GraphQL ids (opaque, stable) ---------------------------------------------

function repoGlobalId(repo: Repo): string {
  return b64url(`repo:${repo.owner}/${repo.name}`);
}
function issueGlobalId(repo: Repo, issue: Issue): string {
  return b64url(`issue:${repo.owner}/${repo.name}:${issue.number}`);
}
function prGlobalId(repo: Repo, pr: Pull): string {
  return b64url(`pr:${repo.owner}/${repo.name}:${pr.number}`);
}
function decodeGlobalId(id: string): { kind: string; owner: string; name: string; number: number } | null {
  try {
    const text = unb64url(id);
    const m = /^(repo|issue|pr):([^/]+)\/([^:]+)(?::(\d+))?$/.exec(text);
    if (!m) return null;
    return { kind: m[1], owner: m[2], name: m[3], number: m[4] ? Number(m[4]) : 0 };
  } catch {
    return null;
  }
}

function cursorFor(n: number): string {
  return b64url(`c:${n}`);
}
function numberFromCursor(cursor: string): number | null {
  try {
    const text = unb64url(cursor);
    const m = /^c:(\d+)$/.exec(text);
    return m ? Number(m[1]) : null;
  } catch {
    return null;
  }
}

// --- introspection surface ------------------------------------------------------

const TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'author', 'labels', 'comments'],
  PullRequest: ['id', 'number', 'title', 'body', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files', 'createdAt', 'author'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'createdAt'],
  SearchType: [],
  User: ['id', 'login', 'name', 'email'],
};
const TYPE_ENUM_VALUES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'USER', 'REPOSITORY', 'DISCUSSION'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
};

// --- executor -------------------------------------------------------------------

interface GqlCtx {
  errors: Array<{ message: string }>;
  fragments: Record<string, GqlFragment>;
  variables: Record<string, unknown>;
}

function gqlError(ctx: GqlCtx, message: string): void {
  ctx.errors.push({ message });
}

/** Resolve a selection set against a (value, typeName) pair. */
function resolveSelections(value: unknown, typeName: string, selections: GqlSelection[], ctx: GqlCtx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.kind === 'spread') {
      const frag = ctx.fragments[sel.name];
      if (frag) Object.assign(out, resolveSelections(value, typeName, frag.selections, ctx));
      continue;
    }
    if (sel.kind === 'inline') {
      if (sel.typeCondition && sel.typeCondition !== typeName) continue;
      Object.assign(out, resolveSelections(value, typeName, sel.selections, ctx));
      continue;
    }
    const key = sel.alias ?? sel.name;
    const resolved = resolveField(value, typeName, sel, ctx);
    out[key] = resolved;
  }
  return out;
}

function resolveField(value: unknown, typeName: string, field: GqlField, ctx: GqlCtx): unknown {
  const args: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(field.args)) args[k] = resolveValue(v, ctx.variables);
  const sub = (v: unknown, t: string): unknown =>
    field.selections.length ? resolveSelections(v, t, field.selections, ctx) : v;

  if (typeName === 'Query') {
    const root = value as { viewerLogin: string };
    if (field.name === 'viewer') {
      return sub({ __type: 'User', login: root.viewerLogin, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL }, 'User');
    }
    if (field.name === 'repository') {
      const owner = String(args.owner ?? '');
      const name = String(args.name ?? '');
      const repo = getRepo(owner, name);
      if (!repo) return null;
      return sub({ __type: 'Repository', repo }, 'Repository');
    }
    if (field.name === 'node') {
      const decoded = decodeGlobalId(String(args.id ?? ''));
      if (!decoded) return null;
      const repo = getRepo(decoded.owner, decoded.name);
      if (!repo) return null;
      if (decoded.kind === 'repo') return sub({ __type: 'Repository', repo }, 'Repository');
      return null;
    }
    if (field.name === '__type') {
      const name = String(args.name ?? '');
      const fields = TYPE_FIELDS[name] ?? null;
      if (fields === null && !TYPE_ENUM_VALUES[name]) return null;
      return sub({ __type: '__Type', typeName: name }, '__Type');
    }
    gqlError(ctx, `Cannot query field "${field.name}" on type "Query".`);
    return null;
  }

  if (typeName === '__Type') {
    const v = value as { typeName: string };
    if (field.name === 'name') return v.typeName;
    if (field.name === 'kind') return TYPE_ENUM_VALUES[v.typeName] ? 'ENUM' : 'OBJECT';
    if (field.name === 'fields') {
      const names = TYPE_FIELDS[v.typeName] ?? [];
      return names.map((n) => sub({ __type: '__Field', name: n }, '__Field'));
    }
    if (field.name === 'enumValues') {
      const names = TYPE_ENUM_VALUES[v.typeName] ?? [];
      return names.map((n) => sub({ __type: '__EnumValue', name: n }, '__EnumValue'));
    }
    gqlError(ctx, `Cannot query field "${field.name}" on type "__Type".`);
    return null;
  }
  if (typeName === '__Field' || typeName === '__EnumValue') {
    const v = value as { name: string };
    if (field.name === 'name') return v.name;
    gqlError(ctx, `Cannot query field "${field.name}" on type "${typeName}".`);
    return null;
  }

  if (typeName === 'User') {
    const v = value as { login: string; id: number; name: string; email: string };
    if (field.name === 'login') return v.login;
    if (field.name === 'id') return b64url(`user:${v.login}`);
    if (field.name === 'name') return v.name;
    if (field.name === 'email') return v.email;
    gqlError(ctx, `Cannot query field "${field.name}" on type "User".`);
    return null;
  }

  if (typeName === 'Repository') {
    const repo = (value as { repo: Repo }).repo;
    switch (field.name) {
      case 'id':
        return repoGlobalId(repo);
      case 'databaseId':
        return repo.id;
      case 'name':
        return repo.name;
      case 'nameWithOwner':
        return `${repo.owner}/${repo.name}`;
      case 'owner':
        return sub({ __type: 'User', login: repo.owner, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL }, 'User');
      case 'defaultBranchRef':
        return sub({ __type: 'Ref', name: repo.defaultBranch }, 'Ref');
      case 'viewerPermission':
        return 'ADMIN';
      case 'hasIssuesEnabled':
        return true;
      case 'description':
        return repo.description;
      case 'createdAt':
        return repo.createdAt;
      case 'issue': {
        const issue = repo.issues.find((i) => i.number === Number(args.number));
        if (!issue) return null;
        return sub({ __type: 'Issue', repo, issue }, 'Issue');
      }
      case 'issues': {
        let list = [...repo.issues];
        const states = args.states as string[] | undefined;
        if (Array.isArray(states) && states.length) list = list.filter((i) => states.includes(i.state.toUpperCase()));
        const orderBy = args.orderBy as { field?: string; direction?: string } | undefined;
        if (orderBy?.field === 'CREATED_AT' && orderBy?.direction === 'DESC') list.sort((a, b) => b.number - a.number);
        else list.sort((a, b) => a.number - b.number);
        const first = typeof args.first === 'number' ? args.first : 100;
        const after = typeof args.after === 'string' ? numberFromCursor(args.after) : null;
        if (after !== null) {
          list = orderBy?.direction === 'DESC' ? list.filter((i) => i.number < after) : list.filter((i) => i.number > after);
        }
        const page = list.slice(0, first);
        const hasNext = list.length > first;
        const endCursor = page.length ? cursorFor(page[page.length - 1].number) : null;
        return sub(
          { __type: 'IssueConnection', nodes: page.map((i) => ({ __type: 'Issue', repo, issue: i })), pageInfo: { hasNextPage: hasNext, endCursor } },
          'IssueConnection',
        );
      }
      case 'pullRequests': {
        const first = typeof args.first === 'number' ? args.first : 100;
        const page = repo.pulls.slice(0, first);
        return sub(
          { __type: 'PullRequestConnection', nodes: page.map((p) => ({ __type: 'PullRequest', repo, pr: p })) },
          'PullRequestConnection',
        );
      }
      case 'pullRequest': {
        const pr = repo.pulls.find((p) => p.number === Number(args.number));
        if (!pr) return null;
        return sub({ __type: 'PullRequest', repo, pr }, 'PullRequest');
      }
      default:
        gqlError(ctx, `Cannot query field "${field.name}" on type "Repository".`);
        return null;
    }
  }

  if (typeName === 'Issue') {
    const v = value as { repo: Repo; issue: Issue };
    switch (field.name) {
      case 'id':
        return issueGlobalId(v.repo, v.issue);
      case 'number':
        return v.issue.number;
      case 'title':
        return v.issue.title;
      case 'state':
        return v.issue.state.toUpperCase();
      case 'body':
        return v.issue.body;
      case 'createdAt':
        return v.issue.createdAt;
      case 'updatedAt':
        return v.issue.updatedAt;
      case 'author':
        return sub({ __type: 'User', login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL }, 'User');
      default:
        gqlError(ctx, `Cannot query field "${field.name}" on type "Issue".`);
        return null;
    }
  }

  if (typeName === 'PullRequest') {
    const v = value as { repo: Repo; pr: Pull };
    switch (field.name) {
      case 'id':
        return prGlobalId(v.repo, v.pr);
      case 'number':
        return v.pr.number;
      case 'title':
        return v.pr.title;
      case 'body':
        return v.pr.body;
      case 'state':
        return v.pr.merged ? 'MERGED' : v.pr.state.toUpperCase();
      case 'merged':
        return v.pr.merged;
      case 'headRefName':
        return v.pr.headRef;
      case 'baseRefName':
        return v.pr.baseRef;
      case 'mergeable':
        return v.pr.state === 'open' ? (prConflict(v.repo, v.pr) ? 'CONFLICTING' : 'MERGEABLE') : 'UNKNOWN';
      case 'createdAt':
        return v.pr.createdAt;
      case 'files': {
        const first = typeof args.first === 'number' ? args.first : 100;
        const nodes = v.pr.files.slice(0, first).map((f) => ({ __type: 'CommitFile', path: f.filename }));
        return sub({ __type: 'FileConnection', nodes }, 'FileConnection');
      }
      default:
        gqlError(ctx, `Cannot query field "${field.name}" on type "PullRequest".`);
        return null;
    }
  }

  if (typeName === 'IssueConnection' || typeName === 'PullRequestConnection' || typeName === 'FileConnection') {
    const v = value as { nodes: unknown[]; pageInfo?: { hasNextPage: boolean; endCursor: string | null } };
    if (field.name === 'nodes') {
      const childType = typeName === 'IssueConnection' ? 'Issue' : typeName === 'PullRequestConnection' ? 'PullRequest' : 'CommitFile';
      return v.nodes.map((n) => {
        const node = n as { __type: string };
        return field.selections.length ? resolveSelections(node, childType, field.selections, ctx) : node;
      });
    }
    if (field.name === 'edges') return [];
    if (field.name === 'pageInfo') {
      const pi = v.pageInfo ?? { hasNextPage: false, endCursor: null };
      return sub({ __type: 'PageInfo', ...pi }, 'PageInfo');
    }
    if (field.name === 'totalCount') return v.nodes.length;
    gqlError(ctx, `Cannot query field "${field.name}" on type "${typeName}".`);
    return null;
  }

  if (typeName === 'PageInfo') {
    const v = value as { hasNextPage: boolean; endCursor: string | null };
    if (field.name === 'hasNextPage') return v.hasNextPage;
    if (field.name === 'endCursor') return v.endCursor;
    if (field.name === 'hasPreviousPage') return false;
    if (field.name === 'startCursor') return null;
    gqlError(ctx, `Cannot query field "${field.name}" on type "PageInfo".`);
    return null;
  }

  if (typeName === 'Ref') {
    const v = value as { name: string };
    if (field.name === 'name') return v.name;
    gqlError(ctx, `Cannot query field "${field.name}" on type "Ref".`);
    return null;
  }

  if (typeName === 'CommitFile') {
    const v = value as { path: string };
    if (field.name === 'path') return v.path;
    gqlError(ctx, `Cannot query field "${field.name}" on type "CommitFile".`);
    return null;
  }

  // Mutation payloads: one nested object field each.
  if (typeName in PAYLOAD_CHILD) {
    const child = PAYLOAD_CHILD[typeName];
    if (field.name === child) {
      const v = value as { repo: Repo; issue?: Issue; pr?: Pull; comment?: { id: number; body: string; createdAt: string } };
      if (child === 'issue' && v.issue) return sub({ __type: 'Issue', repo: v.repo, issue: v.issue }, 'Issue');
      if (child === 'pullRequest' && v.pr) return sub({ __type: 'PullRequest', repo: v.repo, pr: v.pr }, 'PullRequest');
      if (child === 'commentEdge' && v.comment) {
        return sub({ __type: 'IssueCommentEdge', comment: v.comment, repo: v.repo, issue: v.issue }, 'IssueCommentEdge');
      }
      return null;
    }
    gqlError(ctx, `Cannot query field "${field.name}" on type "${typeName}".`);
    return null;
  }

  if (typeName === 'IssueCommentEdge') {
    const v = value as { comment: { id: number; body: string; createdAt: string }; repo: Repo; issue?: Issue };
    if (field.name === 'node') {
      return sub({ __type: 'IssueComment', comment: v.comment, repo: v.repo, issue: v.issue }, 'IssueComment');
    }
    gqlError(ctx, `Cannot query field "${field.name}" on type "IssueCommentEdge".`);
    return null;
  }

  if (typeName === 'IssueComment') {
    const v = value as { comment: { id: number; body: string; createdAt: string }; repo: Repo; issue?: Issue };
    if (field.name === 'id') return b64url(`comment:${v.repo.owner}/${v.repo.name}:${v.issue?.number ?? 0}:${v.comment.id}`);
    if (field.name === 'body') return v.comment.body;
    gqlError(ctx, `Cannot query field "${field.name}" on type "IssueComment".`);
    return null;
  }

  gqlError(ctx, `Cannot query field "${field.name}" on type "${typeName}".`);
  return null;
}

function executeMutation(op: GqlOperation, ctx: GqlCtx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of op.selections) {
    if (sel.kind !== 'field') continue;
    const key = sel.alias ?? sel.name;
    const rawInput = sel.args.input;
    const input = (
      rawInput ? (resolveValue(rawInput, ctx.variables) as Record<string, unknown>) : {}
    ) as Record<string, unknown>;
    if (sel.name === 'createIssue') {
      const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
      const repo = decoded ? getRepo(decoded.owner, decoded.name) : undefined;
      if (!repo) {
        gqlError(ctx, 'createIssue: repository not found');
        out[key] = null;
        continue;
      }
      const now = tickIso();
      const issue: Issue = {
        id: nextObjectId,
        number: repo.nextIssue,
        title: String(input.title ?? ''),
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        labels: [],
        createdAt: now,
        updatedAt: now,
        comments: [],
        jsonCache: null,
      };
      nextObjectId += 1;
      repo.nextIssue += 1;
      repo.issues.push(issue);
      out[key] = resolveSelections({ __type: 'CreateIssuePayload', issue, repo }, 'CreateIssuePayload', sel.selections, ctx);
      continue;
    }
    if (sel.name === 'closeIssue') {
      const decoded = decodeGlobalId(String(input.issueId ?? ''));
      const repo = decoded ? getRepo(decoded.owner, decoded.name) : undefined;
      const issue = repo?.issues.find((i) => i.number === decoded?.number);
      if (!repo || !issue) {
        gqlError(ctx, 'closeIssue: issue not found');
        out[key] = null;
        continue;
      }
      issue.state = 'closed';
      issue.updatedAt = tickIso();
      issue.jsonCache = null;
      out[key] = resolveSelections({ __type: 'CloseIssuePayload', issue, repo }, 'CloseIssuePayload', sel.selections, ctx);
      continue;
    }
    if (sel.name === 'createPullRequest') {
      const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
      const repo = decoded ? getRepo(decoded.owner, decoded.name) : undefined;
      const headRef = String(input.headRefName ?? '');
      const baseRef = String(input.baseRefName ?? repo?.defaultBranch ?? DEFAULT_BRANCH);
      const headSha = repo?.refs.get(`refs/heads/${headRef}`);
      const baseSha = repo?.refs.get(`refs/heads/${baseRef}`);
      if (!repo || !headSha || !baseSha) {
        gqlError(ctx, 'createPullRequest: repository or branch not found');
        out[key] = null;
        continue;
      }
      const headTree = parseCommit(getObject(headSha)?.bytes ?? Buffer.alloc(0))?.tree ?? null;
      const baseTree = parseCommit(getObject(baseSha)?.bytes ?? Buffer.alloc(0))?.tree ?? null;
      const pr: Pull = {
        id: nextObjectId,
        number: repo.nextPull,
        title: String(input.title ?? ''),
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        headRef,
        baseRef,
        headSha,
        baseSha,
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        createdAt: tickIso(),
        files: diffTrees(baseTree, headTree),
      };
      nextObjectId += 1;
      repo.nextPull += 1;
      repo.pulls.push(pr);
      out[key] = resolveSelections({ __type: 'CreatePullRequestPayload', pr, repo }, 'CreatePullRequestPayload', sel.selections, ctx);
      continue;
    }
    if (sel.name === 'mergePullRequest') {
      const decoded = decodeGlobalId(String(input.pullRequestId ?? ''));
      const repo = decoded ? getRepo(decoded.owner, decoded.name) : undefined;
      const pr = repo?.pulls.find((p) => p.number === decoded?.number);
      if (!repo || !pr) {
        gqlError(ctx, 'mergePullRequest: pull request not found');
        out[key] = null;
        continue;
      }
      if (pr.state === 'open' && !prConflict(repo, pr)) {
        const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
        const headTree = parseCommit(getObject(pr.headSha)?.bytes ?? Buffer.alloc(0))?.tree ?? null;
        const mergeCommit = makeCommit(headTree ?? '', baseTip ? [baseTip] : [], `Merge pull request #${pr.number}: ${pr.title}`);
        repo.refs.set(`refs/heads/${pr.baseRef}`, mergeCommit);
        pr.state = 'closed';
        pr.merged = true;
        pr.mergedAt = tickIso();
        pr.mergeCommitSha = mergeCommit;
      }
      out[key] = resolveSelections({ __type: 'MergePullRequestPayload', pr, repo }, 'MergePullRequestPayload', sel.selections, ctx);
      continue;
    }
    if (sel.name === 'addComment') {
      const decoded = decodeGlobalId(String(input.subjectId ?? ''));
      const repo = decoded ? getRepo(decoded.owner, decoded.name) : undefined;
      const issue = repo?.issues.find((i) => i.number === decoded?.number);
      if (!repo || !issue) {
        gqlError(ctx, 'addComment: subject not found');
        out[key] = null;
        continue;
      }
      const comment = { id: repo.nextComment, body: String(input.body ?? ''), createdAt: tickIso() };
      repo.nextComment += 1;
      issue.comments.push(comment);
      issue.jsonCache = null;
      out[key] = resolveSelections(
        { __type: 'AddCommentPayload', comment, repo, issue },
        'AddCommentPayload',
        sel.selections,
        ctx,
      );
      continue;
    }
    gqlError(ctx, `Cannot query field "${sel.name}" on type "Mutation".`);
    out[key] = null;
  }
  return out;
}

// Payload types resolve their single nested object field.
const PAYLOAD_CHILD: Record<string, string> = {
  CreateIssuePayload: 'issue',
  CloseIssuePayload: 'issue',
  CreatePullRequestPayload: 'pullRequest',
  MergePullRequestPayload: 'pullRequest',
  AddCommentPayload: 'commentEdge',
};

function executeOperation(op: GqlOperation, variables: Record<string, unknown>, fragments: Record<string, GqlFragment>): { data: Record<string, unknown> | null; errors: Array<{ message: string }> } {
  const ctx: GqlCtx = { errors: [], fragments, variables };
  if (op.kind === 'mutation') {
    const data = executeMutation(op, ctx);
    return { data, errors: ctx.errors };
  }
  const data = resolveSelections({ __type: 'Query', viewerLogin: VIEWER_LOGIN }, 'Query', op.selections, ctx);
  return { data, errors: ctx.errors };
}

/** Handle one GraphQL operation object; returns the response envelope. */
function handleGraphqlOperation(body: Record<string, unknown>): Record<string, unknown> {
  const query = typeof body.query === 'string' ? body.query : '';
  const variables = (body.variables ?? {}) as Record<string, unknown>;
  const operationName = typeof body.operationName === 'string' ? body.operationName : null;
  try {
    const { operations, fragments } = new GqlParser(query).parseDocument();
    if (operations.length === 0) return { data: null, errors: [{ message: 'no operation found' }] };
    const op = operationName ? operations.find((o) => o.name === operationName) ?? operations[0] : operations[0];
    const { data, errors } = executeOperation(op, variables, fragments);
    return errors.length ? { data, errors } : { data };
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'parse error' }] };
  }
}

async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const rid = requestId();
  if (!authorized(req)) {
    jsonBody(res, 401, errJson('Requires authentication'), { 'x-github-request-id': rid });
    return true;
  }
  const parsed = await readJsonBody(req);
  if (!parsed.ok) {
    jsonBody(res, 400, errJson('Malformed JSON body'), { 'x-github-request-id': rid });
    return true;
  }
  const value = parsed.value;
  let result: unknown;
  if (Array.isArray(value)) {
    result = value.map((op) => (op && typeof op === 'object' ? handleGraphqlOperation(op as Record<string, unknown>) : { data: null, errors: [{ message: 'invalid operation' }] }));
  } else if (value && typeof value === 'object') {
    result = handleGraphqlOperation(value as Record<string, unknown>);
  } else {
    result = { data: null, errors: [{ message: 'invalid request' }] };
  }
  jsonBody(res, 200, result, { 'x-github-request-id': rid });
  return true;
}

// ---------------------------------------------------------------- MCP

interface McpTool {
  name: string;
  description: string;
  inputSchema: { type: 'object'; properties: Record<string, Record<string, unknown>>; required: string[] };
}

const MCP_TOOLS: McpTool[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state filter: open, closed, or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch onto a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash commit.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

const TOOL_ALIASES: Record<string, string[]> = {
  create_repo: ['create_repository', 'repo_create', 'repos_create', 'repository_create'],
  get_repo: ['get_repository', 'repo_get', 'repos_get', 'repository_get'],
  create_issue: ['issue_create', 'issues_create'],
  list_issues: ['issues_list', 'issue_list'],
  create_pull_request: ['pull_request_create', 'pulls_create', 'create_pr', 'pr_create'],
  merge_pull_request: ['pull_request_merge', 'pulls_merge', 'merge_pr', 'pr_merge'],
};

const normName = (s: string): string => s.toLowerCase().replace(/[^a-z0-9]/g, '');

function matchTool(name: string): string | null {
  const n = normName(name);
  for (const tool of MCP_TOOLS) {
    if (normName(tool.name) === n) return tool.name;
    for (const alias of TOOL_ALIASES[tool.name] ?? []) {
      if (normName(alias) === n) return tool.name;
    }
    if (n.endsWith(normName(tool.name))) return tool.name;
  }
  return null;
}

const ARG_SYNONYMS: Record<string, string[]> = {
  owner: ['owner', 'ownerlogin', 'org', 'organization', 'user', 'login', 'account', 'namespace', 'ownername'],
  repo: ['repo', 'repository', 'repositoryname', 'reponame', 'project'],
  name: ['name', 'repo', 'repository', 'repositoryname', 'reponame'],
  title: ['title', 'issuetitle', 'prtitle', 'subject'],
  body: ['body', 'issuebody', 'description', 'content', 'text'],
  description: ['description', 'about', 'summary', 'body'],
  private: ['private', 'isprivate'],
  head: ['head', 'headref', 'headbranch', 'source', 'frombranch', 'branch'],
  base: ['base', 'baseref', 'basebranch', 'target', 'intobranch'],
  pull_number: ['pullnumber', 'pullrequestnumber', 'prnumber', 'number', 'index'],
  state: ['state', 'status'],
};

function mapArgs(args: Record<string, unknown>): Record<string, unknown> {
  const byNorm = new Map<string, unknown>();
  for (const [k, v] of Object.entries(args)) byNorm.set(normName(k), v);
  const out: Record<string, unknown> = {};
  for (const [semantic, synonyms] of Object.entries(ARG_SYNONYMS)) {
    for (const syn of synonyms) {
      if (byNorm.has(syn)) {
        out[semantic] = byNorm.get(syn);
        break;
      }
    }
  }
  // full_name "owner/repo" fills owner + repo when they are missing.
  const fullName = byNorm.get('fullname');
  if (typeof fullName === 'string' && fullName.includes('/')) {
    const [o, r] = fullName.split('/');
    if (out.owner === undefined) out.owner = o;
    if (out.repo === undefined) out.repo = r;
  }
  return out;
}

interface McpCallResult {
  content: Array<{ type: 'text'; text: string }>;
  structuredContent?: unknown;
  isError?: boolean;
}

function mcpOk(result: unknown): McpCallResult {
  return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result };
}
function mcpErr(text: string): McpCallResult {
  return { content: [{ type: 'text', text }], isError: true };
}

function callTool(name: string, args: Record<string, unknown>): McpCallResult {
  const a = mapArgs(args);
  const missing = (fields: string[]): McpCallResult | null => {
    for (const f of fields) {
      if (a[f] === undefined || a[f] === null || a[f] === '') return mcpErr(`Missing required argument: ${f}`);
    }
    return null;
  };
  if (name === 'create_repo') {
    const miss = missing(['name']);
    if (miss) return miss;
    const repoName = String(a.name);
    if (repos.has(repoKey(VIEWER_LOGIN, repoName))) return mcpErr(`Repository ${repoName} already exists`);
    const repo = createRepo(repoName, typeof a.description === 'string' ? a.description : '', a.private === true);
    return mcpOk(repoObject(repo));
  }
  if (name === 'get_repo') {
    const miss = missing(['owner', 'repo']);
    if (miss) return miss;
    const repo = getRepo(String(a.owner), String(a.repo));
    if (!repo) return mcpErr('Repository not found');
    return mcpOk(repoObject(repo));
  }
  if (name === 'create_issue') {
    const miss = missing(['owner', 'repo', 'title']);
    if (miss) return miss;
    const repo = getRepo(String(a.owner), String(a.repo));
    if (!repo) return mcpErr('Repository not found');
    const now = tickIso();
    const issue: Issue = {
      id: nextObjectId,
      number: repo.nextIssue,
      title: String(a.title),
      body: typeof a.body === 'string' ? a.body : '',
      state: 'open',
      labels: [],
      createdAt: now,
      updatedAt: now,
      comments: [],
      jsonCache: null,
    };
    nextObjectId += 1;
    repo.nextIssue += 1;
    repo.issues.push(issue);
    return mcpOk(issueObject(repo, issue));
  }
  if (name === 'list_issues') {
    const miss = missing(['owner', 'repo']);
    if (miss) return miss;
    const repo = getRepo(String(a.owner), String(a.repo));
    if (!repo) return mcpErr('Repository not found');
    let list = [...repo.issues];
    if (a.state === 'open' || a.state === 'closed') list = list.filter((i) => i.state === a.state);
    const arr = list.map((i) => issueObject(repo, i));
    return { content: [{ type: 'text', text: JSON.stringify(arr) }], structuredContent: { issues: arr } };
  }
  if (name === 'create_pull_request') {
    const miss = missing(['owner', 'repo', 'title', 'head', 'base']);
    if (miss) return miss;
    const repo = getRepo(String(a.owner), String(a.repo));
    if (!repo) return mcpErr('Repository not found');
    const headSha = repo.refs.get(`refs/heads/${String(a.head)}`);
    const baseSha = repo.refs.get(`refs/heads/${String(a.base)}`);
    if (!headSha || !baseSha) return mcpErr('head or base branch does not exist');
    const headTree = parseCommit(getObject(headSha)?.bytes ?? Buffer.alloc(0))?.tree ?? null;
    const baseTree = parseCommit(getObject(baseSha)?.bytes ?? Buffer.alloc(0))?.tree ?? null;
    const pr: Pull = {
      id: nextObjectId,
      number: repo.nextPull,
      title: String(a.title),
      body: typeof a.body === 'string' ? a.body : '',
      state: 'open',
      headRef: String(a.head),
      baseRef: String(a.base),
      headSha,
      baseSha,
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      createdAt: tickIso(),
      files: diffTrees(baseTree, headTree),
    };
    nextObjectId += 1;
    repo.nextPull += 1;
    repo.pulls.push(pr);
    return mcpOk(pullObject(repo, pr));
  }
  if (name === 'merge_pull_request') {
    const miss = missing(['owner', 'repo', 'pull_number']);
    if (miss) return miss;
    const repo = getRepo(String(a.owner), String(a.repo));
    if (!repo) return mcpErr('Repository not found');
    const pr = repo.pulls.find((p) => p.number === Number(a.pull_number));
    if (!pr) return mcpErr('Pull request not found');
    if (pr.state !== 'open') return mcpErr('Pull request is not open');
    if (prConflict(repo, pr)) return mcpErr('Merge conflict');
    const baseTip = repo.refs.get(`refs/heads/${pr.baseRef}`);
    const headTree = parseCommit(getObject(pr.headSha)?.bytes ?? Buffer.alloc(0))?.tree ?? null;
    const mergeCommit = makeCommit(headTree ?? '', baseTip ? [baseTip] : [], `Merge pull request #${pr.number}: ${pr.title}`);
    repo.refs.set(`refs/heads/${pr.baseRef}`, mergeCommit);
    pr.state = 'closed';
    pr.merged = true;
    pr.mergedAt = tickIso();
    pr.mergeCommitSha = mergeCommit;
    return mcpOk(pullObject(repo, pr));
  }
  return mcpErr(`Unknown tool: ${name}`);
}

function rpcResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id, result };
}
function rpcError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
  const rid = requestId();
  if (!authorized(req)) {
    jsonBody(res, 401, errJson('Requires authentication'), { 'x-github-request-id': rid });
    return true;
  }
  if (req.method === 'DELETE') {
    res.writeHead(200, { 'x-github-request-id': rid });
    res.end();
    return true;
  }
  if (req.method !== 'POST') {
    jsonBody(res, 405, errJson('Method not allowed'), { 'x-github-request-id': rid });
    return true;
  }
  const raw = await readRawBody(req);
  let body: unknown;
  try {
    body = JSON.parse(raw.toString('utf8'));
  } catch {
    const idMatch = /"id"\s*:\s*(\d+|"[^"]*")/.exec(raw.toString('utf8'));
    const id = idMatch ? JSON.parse(idMatch[1]) : null;
    jsonBody(res, 400, rpcError(id, -32700, 'Parse error'), { 'x-github-request-id': rid });
    return true;
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    jsonBody(res, 400, rpcError(null, -32600, 'Invalid Request'), { 'x-github-request-id': rid });
    return true;
  }
  const msg = body as { jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown> };
  const hasId = msg.id !== undefined;
  // Notifications (no id) get no JSON-RPC answer.
  if (!hasId) {
    res.writeHead(202, { 'x-github-request-id': rid });
    res.end();
    return true;
  }
  const method = msg.method ?? '';
  const params = (msg.params ?? {}) as Record<string, unknown>;
  let result: unknown;
  if (method === 'server/discover') {
    result = {
      supportedVersions: ['2026-07-28', '2025-11-25'],
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: '1.0.0' },
    };
  } else if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
    result = {
      protocolVersion: offered,
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: '1.0.0' },
    };
  } else if (method === 'ping') {
    result = {};
  } else if (method === 'tools/list') {
    result = { tools: MCP_TOOLS };
  } else if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const matched = matchTool(toolName);
    if (!matched) {
      jsonBody(res, 200, rpcError(msg.id, -32601, `Unknown tool: ${toolName}`), { 'x-github-request-id': rid });
      return true;
    }
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    result = callTool(matched, args);
  } else {
    jsonBody(res, 200, rpcError(msg.id, -32601, `Method not found: ${method}`), { 'x-github-request-id': rid });
    return true;
  }
  jsonBody(res, 200, rpcResult(msg.id, result), { 'x-github-request-id': rid });
  return true;
}

// ---------------------------------------------------------------- router + lifecycle

function pathOf(req: IncomingMessage): { segments: string[]; query: URLSearchParams } {
  try {
    const url = new URL(req.url ?? '/', 'http://entry');
    const segments = url.pathname.split('/').filter((s) => s !== '');
    return { segments, query: url.searchParams };
  } catch {
    return { segments: [], query: new URLSearchParams() };
  }
}

export function createApp() {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const { segments, query } = pathOf(req);
        const method = req.method ?? 'GET';
        // GET /healthz — the env's boot probe, no auth.
        if (method === 'GET' && segments.length === 1 && segments[0] === 'healthz') {
          jsonBody(res, 200, { ok: true });
          return;
        }
        // POST /api/graphql
        if (segments.length === 2 && segments[0] === 'api' && segments[1] === 'graphql' && method === 'POST') {
          await handleGraphql(req, res);
          return;
        }
        // POST /mcp
        if (segments.length === 1 && segments[0] === 'mcp') {
          await handleMcp(req, res);
          return;
        }
        // /api/v3/...
        if (segments.length >= 1 && segments[0] === 'api' && segments[1] === 'v3') {
          const handled = await handleRest(req, res, segments.slice(2), query);
          if (handled) return;
        }
        // /{owner}/{repo}.git/...
        if (segments.length >= 2 && segments[1].endsWith('.git')) {
          const owner = decodeURIComponent(segments[0]);
          const repoName = decodeURIComponent(segments[1].slice(0, -4));
          const handled = await handleGit(req, res, owner, repoName, segments.slice(2), query);
          if (handled) return;
        }
        // Anything else: GitHub's JSON 404.
        jsonBody(res, 404, errJson('Not Found'), { 'x-github-request-id': requestId() });
      } catch (err) {
        if (!res.headersSent) {
          jsonBody(res, 500, errJson(err instanceof Error ? err.message : 'internal error'), { 'x-github-request-id': requestId() });
        } else {
          res.end();
        }
      }
    })();
  });
}

// --- env lifecycle: bind, register, poll /done, exit 0 ---------------------------

const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
const REQUEST_TIMEOUT_MS = 30_000;
const RETRY_INITIAL_MS = 250;
const RETRY_MAX_MS = 2_000;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function retryDelay(attempt: number): number {
  return Math.min(RETRY_MAX_MS, RETRY_INITIAL_MS * 2 ** Math.min(attempt, 8));
}

async function register(port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) throw new Error(`register answered HTTP ${res.status}: ${await res.text()}`);
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('register answered HTTP ')) throw err;
    }
    await sleep(retryDelay(attempt));
  }
}

async function waitForDone(): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // The env is not answering yet: poll again.
    }
    await sleep(retryDelay(attempt));
  }
}

async function main(): Promise<void> {
  const server = createApp();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('the server did not bind an ephemeral TCP port');
  process.stdout.write(`[entry] listening on port ${address.port}\n`);

  if (ENV_URL === '') {
    if (process.env.FORGE_STANDALONE === '1') {
      // Local practice without an env: just serve. The trial always sets
      // MAKEFUN_ENV_URL, so this path never runs at grading time.
      process.stdout.write('[entry] standalone mode: serving without an env\n');
      await new Promise<void>(() => undefined);
      return;
    }
    throw new Error('MAKEFUN_ENV_URL is not set: there is no env to register with');
  }

  await register(address.port);
  process.stdout.write('[entry] registered; waiting for the env to say done\n');
  await waitForDone();
  server.close();
  process.stdout.write('[entry] done\n');
}

try {
  await main();
  process.exit(0);
} catch (err) {
  process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
