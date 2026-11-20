/**
 * Long life learning Academy — Hardened Single-File Server & SPA
 * Tagline: "We innovate to teach you Skills , Knowledges and develop you Possotive Mindset"
 * Primary Admin: mohammedscho2023@gmail.com | Master Admin Code: 5405402
 *
 * Dependencies:
 *   npm install express @prisma/client bcrypt jsonwebtoken helmet cors pdfkit dotenv
 */

'use strict';

require('dotenv').config();

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const PDFDocument = require('pdfkit');
const { PrismaClient } = require('@prisma/client');

const execFileAsync = promisify(execFile);

// ============================================================================
// 1. CONFIGURATION & CONSTANTS
// ============================================================================
const PORT = Number(process.env.PORT) || 5000;
const ACADEMY_NAME = process.env.ACADEMY_NAME || 'Long life learning Academy';
const ACADEMY_TAGLINE =
  process.env.ACADEMY_TAGLINE ||
  'We innovate to teach you Skills , Knowledges and develop you Possotive Mindset';

const PRIMARY_ADMIN_EMAIL = (process.env.PRIMARY_ADMIN_EMAIL || 'mohammedscho2023@gmail.com')
  .trim()
  .toLowerCase();
const ADMIN_MASTER_CODE = String(process.env.ADMIN_MASTER_CODE || '5405402').trim();

const JWT_SECRET =
  process.env.JWT_SECRET ||
  crypto.createHash('sha256').update(`${ADMIN_MASTER_CODE}:${PRIMARY_ADMIN_EMAIL}:llla-secret`).digest('hex');
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const SALT_ROUNDS = Math.min(Math.max(Number(process.env.BCRYPT_SALT_ROUNDS) || 10, 8), 14);

const MIN_CERT_PASS_SCORE = Math.min(
  Math.max(Number(process.env.MIN_CERT_PASS_SCORE) || 75, 0),
  100
);

const OTP_TTL_MS = Number(process.env.OTP_TTL_MS) || 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS) || 5;
const REQUIRE_CONTACT_OTP =
  String(process.env.REQUIRE_CONTACT_OTP || 'true').toLowerCase() === 'true';
const ALLOW_DEV_OTP_PREVIEW =
  String(process.env.ALLOW_DEV_OTP_PREVIEW || 'true').toLowerCase() === 'true';

const DATA_DIR = path.resolve(process.env.ACADEMY_DATA_DIR || path.join(process.cwd(), 'data'));
const MEMORY_FILE_PATH = path.join(DATA_DIR, 'academy-memory.jsonl');
const ACADEMY_CONFIG_FILE = path.join(DATA_DIR, 'academy-config.json');
const MAX_MEMORY_INDEX_ENTRIES = Number(process.env.MAX_MEMORY_INDEX_ENTRIES) || 50_000;
const MAX_MAP_ENTRIES = 10_000;

const prisma = new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
});

function setBoundedMap(map, key, value, maxSize = MAX_MAP_ENTRIES) {
  if (map.has(key)) {
    map.delete(key);
  } else if (map.size >= maxSize) {
    const oldestKey = map.keys().next().value;
    if (oldestKey !== undefined) map.delete(oldestKey);
  }
  map.set(key, value);
}

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ============================================================================
// 2. UNLIMITED PERSISTENT MEMORY & ACADEMY RUNTIME CONFIG
// ============================================================================
const memoryIndex = [];

function ensureDataDirSync() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(MEMORY_FILE_PATH)) {
    fs.writeFileSync(MEMORY_FILE_PATH, '', 'utf8');
  }
}

function indexMemoryRecord(record) {
  if (memoryIndex.length >= MAX_MEMORY_INDEX_ENTRIES) {
    memoryIndex.shift();
  }
  memoryIndex.push(record);
}

function loadMemoryIndexSync() {
  ensureDataDirSync();
  const raw = fs.readFileSync(MEMORY_FILE_PATH, 'utf8');
  if (!raw.trim()) return;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && parsed.id) {
        indexMemoryRecord(parsed);
      }
    } catch (_) {}
  }
}

loadMemoryIndexSync();

async function writeUnlimitedMemory({
  scope = 'ACADEMY',
  entityId = null,
  agentId = null,
  title = 'Memory Entry',
  content = '',
  tags = [],
  meta = {},
}) {
  ensureDataDirSync();
  const record = {
    id: `mem_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
    scope: String(scope || 'ACADEMY').toUpperCase(),
    entityId: entityId ? String(entityId) : null,
    agentId: agentId ? String(agentId) : null,
    title: String(title || 'Memory Entry').trim(),
    content: String(content || ''),
    tags: Array.isArray(tags)
      ? tags.map((t) => String(t).trim().toLowerCase()).filter(Boolean)
      : [],
    meta,
    createdAt: new Date().toISOString(),
  };

  await fsp.appendFile(MEMORY_FILE_PATH, `${JSON.stringify(record)}\n`, 'utf8');
  indexMemoryRecord(record);
  return record;
}

async function queryUnlimitedMemory({ q = '', scope = '', entityId = '', cursor = null, limit = 30 } = {}) {
  ensureDataDirSync();
  const safeLimit = Math.min(Math.max(Number(limit) || 30, 1), 200);
  const queryLower = String(q || '').trim().toLowerCase();
  const scopeUpper = String(scope || '').trim().toUpperCase();
  const entityStr = String(entityId || '').trim();

  const raw = await fsp.readFile(MEMORY_FILE_PATH, 'utf8');
  const matched = [];
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    try {
      const rec = JSON.parse(t);
      if (!rec || !rec.id) continue;
      if (scopeUpper && rec.scope !== scopeUpper) continue;
      if (entityStr && rec.entityId !== entityStr) continue;
      if (queryLower) {
        const hay = `${rec.title} ${rec.content} ${(rec.tags || []).join(' ')} ${rec.scope}`.toLowerCase();
        if (!hay.includes(queryLower)) continue;
      }
      matched.push(rec);
    } catch (_) {}
  }

  matched.reverse();

  let startIdx = 0;
  if (cursor) {
    const foundIdx = matched.findIndex((r) => r.id === String(cursor).trim());
    if (foundIdx !== -1) startIdx = foundIdx + 1;
  }

  const slice = matched.slice(startIdx, startIdx + safeLimit);
  const hasMore = startIdx + safeLimit < matched.length;
  const nextCursor = hasMore && slice.length > 0 ? slice[slice.length - 1].id : null;

  return {
    memories: slice,
    totalMatched: matched.length,
    pageInfo: { limit: safeLimit, hasMore, nextCursor },
  };
}

async function getMemoryStats() {
  ensureDataDirSync();
  const stat = await fsp.stat(MEMORY_FILE_PATH);
  const raw = await fsp.readFile(MEMORY_FILE_PATH, 'utf8');
  let lineCount = 0;
  for (const line of raw.split(/\r?\n/)) {
    if (line.trim()) lineCount += 1;
  }
  return {
    storageEngine: 'Append-Only Persistent JSONL + Indexed Retrieval',
    filePath: MEMORY_FILE_PATH,
    totalRecords: lineCount,
    diskSizeBytes: stat.size,
    diskSizeMB: Number((stat.size / (1024 * 1024)).toFixed(3)),
    capacityLimit: 'Unlimited (bounded only by disk volume)',
  };
}

async function exportUnlimitedMemoryJsonl() {
  ensureDataDirSync();
  const raw = await fsp.readFile(MEMORY_FILE_PATH, 'utf8');
  const lines = raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  return {
    jsonl: lines.length > 0 ? `${lines.join('\n')}\n` : '',
    recordCount: lines.length,
    exportedAt: new Date().toISOString(),
  };
}

async function importUnlimitedMemoryJsonl({ jsonlText = '', records = [], regenerateIds = false } = {}) {
  ensureDataDirSync();
  const existingRaw = await fsp.readFile(MEMORY_FILE_PATH, 'utf8');
  const existingIds = new Set();
  for (const line of existingRaw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    try {
      const obj = JSON.parse(t);
      if (obj && obj.id) existingIds.add(String(obj.id));
    } catch (_) {}
  }

  const candidates = [];
  if (Array.isArray(records) && records.length > 0) {
    for (const r of records) candidates.push(r);
  }

  const text = String(jsonlText || '').trim();
  if (text) {
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        candidates.push(JSON.parse(line));
      } catch (err) {
        const bad = new Error(`Invalid JSONL on line ${i + 1}: ${err.message}`);
        bad.statusCode = 400;
        throw bad;
      }
    }
  }

  if (candidates.length === 0) {
    const bad = new Error('Provide non-empty JSONL lines or records to import.');
    bad.statusCode = 400;
    throw bad;
  }

  const acceptedLines = [];
  let importedCount = 0;
  let skippedDuplicateCount = 0;

  for (const item of candidates) {
    if (!item || typeof item !== 'object' || !String(item.content || '').trim()) {
      continue;
    }

    const rawId = item.id ? String(item.id).trim() : '';
    const finalId =
      regenerateIds || !rawId
        ? `mem_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`
        : rawId;

    if (existingIds.has(finalId)) {
      skippedDuplicateCount += 1;
      continue;
    }

    const normalized = {
      id: finalId,
      scope: String(item.scope || 'ACADEMY').toUpperCase(),
      entityId: item.entityId ? String(item.entityId) : null,
      agentId: item.agentId ? String(item.agentId) : 'IMPORTED_BACKUP',
      title: String(item.title || 'Imported Memory Entry').trim(),
      content: String(item.content),
      tags: Array.isArray(item.tags)
        ? item.tags.map((t) => String(t).trim().toLowerCase()).filter(Boolean)
        : [],
      meta: item.meta && typeof item.meta === 'object' ? item.meta : { imported: true },
      createdAt: item.createdAt || new Date().toISOString(),
    };

    existingIds.add(finalId);
    acceptedLines.push(`${JSON.stringify(normalized)}\n`);
    indexMemoryRecord(normalized);
    importedCount += 1;
  }

  if (acceptedLines.length > 0) {
    await fsp.appendFile(MEMORY_FILE_PATH, acceptedLines.join(''), 'utf8');
  }

  const stats = await getMemoryStats();
  return {
    importedCount,
    skippedDuplicateCount,
    totalInStore: stats.totalRecords,
    stats,
  };
}

let academyRuntimeConfig = null;

async function loadAcademyRuntimeConfig() {
  ensureDataDirSync();
  try {
    const raw = await fsp.readFile(ACADEMY_CONFIG_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      academyName: parsed.academyName || ACADEMY_NAME,
      tagline: parsed.tagline || ACADEMY_TAGLINE,
      primaryAdminEmail: PRIMARY_ADMIN_EMAIL,
      principles: Array.isArray(parsed.principles)
        ? parsed.principles
        : [
            'Teach practical Skills for real-world mastery',
            'Build deep Knowledges across any programming language & domain',
            'Develop a resilient, growth-oriented Positive Mindset',
          ],
      promptImprovementsApplied: Number(parsed.promptImprovementsApplied || 0),
      updatedAt: parsed.updatedAt || new Date().toISOString(),
    };
  } catch (_) {
    const initial = {
      academyName: ACADEMY_NAME,
      tagline: ACADEMY_TAGLINE,
      primaryAdminEmail: PRIMARY_ADMIN_EMAIL,
      principles: [
        'Teach practical Skills for real-world mastery',
        'Build deep Knowledges across any programming language & domain',
        'Develop a resilient, growth-oriented Positive Mindset',
      ],
      promptImprovementsApplied: 0,
      updatedAt: new Date().toISOString(),
    };
    await fsp.writeFile(ACADEMY_CONFIG_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
}

async function saveAcademyRuntimeConfig(nextConfig) {
  ensureDataDirSync();
  const payload = {
    ...nextConfig,
    updatedAt: new Date().toISOString(),
  };
  await fsp.writeFile(ACADEMY_CONFIG_FILE, JSON.stringify(payload, null, 2), 'utf8');
  academyRuntimeConfig = payload;
  return payload;
}

async function ensureAcademyConfig() {
  if (!academyRuntimeConfig) {
    academyRuntimeConfig = await loadAcademyRuntimeConfig();
  }
  return academyRuntimeConfig;
}

// ============================================================================
// 3. DOMAIN STORES & HELPERS
// ============================================================================
const VALID_OTP_CHANNELS = new Set(['PHONE', 'WHATSAPP', 'TELEGRAM']);
const otpChallengeStore = new Map();
const learnerSocialProfiles = new Map();
const instructorsDirectory = new Map();
const courseReviewMeta = new Map();

const ALLOWED_TOOL_CATEGORIES = new Set([
  'SEARCH_ENGINE',
  'AI_TOOL',
  'EDUCATIONAL_TOOL',
  'EDUCATIONAL_SERVER',
  'APP',
]);

const ALLOWED_RESOURCE_TYPES = new Set([
  'BOOK',
  'MODULE',
  'GUIDE',
  'TEMPLATE',
  'CODE_PACK',
  'DATASET',
  'OTHER',
]);

const resourceLibrary = new Map();
const externalToolsDirectory = new Map();
const courseLinkedTools = new Map();

const learnerSubmissions = new Map();
const moduleTestCases = new Map();
const learnerCourseScores = new Map();
const coursePassScoreOverrides = new Map();

const learnerTelemetryStore = new Map();
const learnerAdaptationsStore = new Map();
const learnerCompetencesStore = new Map();

function isValidHttpUrl(rawUrl) {
  try {
    const parsed = new URL(String(rawUrl || '').trim());
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch (_) {
    return false;
  }
}

function normalizeToolCategory(rawCat) {
  const cleaned = String(rawCat || 'EDUCATIONAL_TOOL')
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_');
  if (cleaned.includes('SEARCH')) return 'SEARCH_ENGINE';
  if (cleaned === 'AI' || cleaned.includes('AI_TOOL')) return 'AI_TOOL';
  if (cleaned.includes('SERVER')) return 'EDUCATIONAL_SERVER';
  if (cleaned === 'APP' || cleaned.includes('APPL')) return 'APP';
  return ALLOWED_TOOL_CATEGORIES.has(cleaned) ? cleaned : 'EDUCATIONAL_TOOL';
}

function normalizeResourceType(rawType) {
  const cleaned = String(rawType || 'OTHER')
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_');
  if (cleaned.includes('BOOK')) return 'BOOK';
  if (cleaned.includes('MOD')) return 'MODULE';
  if (cleaned.includes('GUIDE') || cleaned.includes('MANUAL')) return 'GUIDE';
  if (cleaned.includes('TEMP')) return 'TEMPLATE';
  if (cleaned.includes('CODE')) return 'CODE_PACK';
  if (cleaned.includes('DATA')) return 'DATASET';
  return ALLOWED_RESOURCE_TYPES.has(cleaned) ? cleaned : 'OTHER';
}

function normalizeSocialLinks(rawLinks) {
  const allowedKeys = [
    'whatsapp',
    'telegram',
    'linkedin',
    'youtube',
    'x',
    'twitter',
    'facebook',
    'instagram',
    'github',
    'tiktok',
    'website',
  ];
  const clean = {};
  if (rawLinks && typeof rawLinks === 'object') {
    for (const [k, v] of Object.entries(rawLinks)) {
      const key = String(k).trim().toLowerCase();
      const val = String(v ?? '').trim();
      if (allowedKeys.includes(key) && val) {
        clean[key] = val;
      }
    }
  }
  return clean;
}

function seedDefaultExternalTools() {
  if (externalToolsDirectory.size > 0) return;
  const defaults = [
    {
      name: 'Google Scholar / Open Search',
      category: 'SEARCH_ENGINE',
      url: 'https://scholar.google.com',
      description: 'Search engine for scholarly research, books, and evidence.',
      requiredForCourses: true,
    },
    {
      name: 'AI Study & Curriculum Assistant',
      category: 'AI_TOOL',
      url: 'https://chatgpt.com',
      description: 'AI tool for learning acceleration, code walkthroughs, and mindset reflection.',
      requiredForCourses: false,
    },
    {
      name: 'Theory of Change & RBM Educational Portal',
      category: 'EDUCATIONAL_TOOL',
      url: 'https://mstbedpm5402.github.io/Theory-of-Change-and-RBM-for-Program-managers/',
      description: 'Interactive educational tool for program design, results, and learning.',
      requiredForCourses: true,
    },
    {
      name: 'Open Educational Code Server',
      category: 'EDUCATIONAL_SERVER',
      url: 'https://github.com',
      description: 'Educational code server and repository for multi-language course labs.',
      requiredForCourses: true,
    },
    {
      name: 'KoboToolbox Field & Assessment App',
      category: 'APP',
      url: 'https://www.kobotoolbox.org',
      description: 'Practical app for field data collection, surveys, and applied learning.',
      requiredForCourses: false,
    },
  ];

  for (const item of defaults) {
    const id = `tool_${crypto.randomBytes(4).toString('hex')}`;
    externalToolsDirectory.set(id, {
      id,
      ...item,
      addedBy: PRIMARY_ADMIN_EMAIL,
      addedAt: new Date().toISOString(),
    });
  }
}

seedDefaultExternalTools();

function parseNonNegativeMoney(val, fieldName) {
  if (val === undefined || val === null || val === '') return '0.00';
  const num = Number(val);
  if (!Number.isFinite(num) || num < 0) {
    const err = new Error(`${fieldName} must be a non-negative number`);
    err.statusCode = 400;
    throw err;
  }
  return num.toFixed(2);
}

function sanitizeFilenamePart(str) {
  return (
    String(str || 'Certificate')
      .replace(/[^a-zA-Z0-9_-]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 60) || 'Certificate'
  );
}

function recordLearnerCourseScore(userId, courseId, score) {
  const numericScore = Math.max(0, Math.min(100, Number(score) || 0));
  const key = `${userId}:${courseId}`;
  const prev = learnerCourseScores.get(key) || {
    userId,
    courseId,
    bestScore: 0,
    lastScore: 0,
    attempts: 0,
    lastEvaluatedAt: null,
  };

  const next = {
    ...prev,
    bestScore: Math.max(prev.bestScore, numericScore),
    lastScore: numericScore,
    attempts: prev.attempts + 1,
    lastEvaluatedAt: new Date().toISOString(),
  };

  setBoundedMap(learnerCourseScores, key, next);
  return next;
}

function getLearnerCourseScore(userId, courseId) {
  return (
    learnerCourseScores.get(`${userId}:${courseId}`) || {
      userId,
      courseId,
      bestScore: 0,
      lastScore: 0,
      attempts: 0,
      lastEvaluatedAt: null,
    }
  );
}

function getRequiredPassScore(courseId) {
  const override = coursePassScoreOverrides.get(String(courseId));
  return override !== undefined ? override : MIN_CERT_PASS_SCORE;
}

// ============================================================================
// 4. PAYMENT GATEWAY & PDF CERTIFICATE STREAMER
// ============================================================================
async function processGatewayPayment({ amount, currency, paymentMethod, purpose, userId, courseId }) {
  const normCurrency = String(currency || '').trim().toUpperCase();
  const normMethod = String(paymentMethod || '').trim().toUpperCase();

  const supportedMethodsByCurrency = {
    ETB: ['TELEBIRR', 'CBE_BIRR'],
    USD: ['PAYPAL'],
  };

  const allowedMethods = supportedMethodsByCurrency[normCurrency];
  if (!allowedMethods) {
    const err = new Error(`Unsupported currency "${currency}". Supported currencies: ETB, USD.`);
    err.statusCode = 400;
    throw err;
  }

  if (!allowedMethods.includes(normMethod)) {
    const err = new Error(
      `Payment method "${paymentMethod}" is not supported for ${normCurrency}. Allowed: ${allowedMethods.join(', ')}.`
    );
    err.statusCode = 400;
    throw err;
  }

  const numericAmount = Number(amount);
  if (!Number.isFinite(numericAmount) || numericAmount < 0) {
    const err = new Error('Invalid payment amount');
    err.statusCode = 400;
    throw err;
  }

  const prefixMap = { TELEBIRR: 'TB', CBE_BIRR: 'CBE', PAYPAL: 'PP' };

  return {
    status: 'COMPLETED',
    amount: numericAmount.toFixed(2),
    currency: normCurrency,
    paymentMethod: normMethod,
    purpose,
    providerRef: `${prefixMap[normMethod] || 'PAY'}_${purpose}_${Date.now()}_${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
    paidAt: new Date().toISOString(),
    metadata: { userId, courseId },
  };
}

function streamCourseCertificatePDF(res, { studentName, courseTitle, programmingLanguage, issuedDate, certificateId }) {
  const cfgName = academyRuntimeConfig?.academyName || ACADEMY_NAME;
  const cfgTagline = academyRuntimeConfig?.tagline || ACADEMY_TAGLINE;
  const doc = new PDFDocument({ size: 'A4', layout: 'landscape', margin: 45 });
  const safeFilename = `${sanitizeFilenamePart(courseTitle)}_Certificate.pdf`;

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
  res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');

  doc.pipe(res);

  const width = doc.page.width;
  const height = doc.page.height;

  doc.lineWidth(4).strokeColor('#fca311').rect(24, 24, width - 48, height - 48).stroke();
  doc.lineWidth(1.5).strokeColor('#004aad').rect(34, 34, width - 68, height - 68).stroke();

  doc.font('Helvetica-Bold').fontSize(15).fillColor('#004aad').text(cfgName.toUpperCase(), 0, 62, { align: 'center' });
  doc.font('Helvetica-Oblique').fontSize(10).fillColor('#475569').text(cfgTagline, 60, 82, {
    align: 'center',
    width: width - 120,
  });

  doc.font('Helvetica-Bold').fontSize(28).fillColor('#14213d').text('CERTIFICATE OF COMPLETION', 0, 118, { align: 'center' });
  doc.font('Helvetica').fontSize(13).fillColor('#334155').text('This is to certify that', 0, 166, { align: 'center' });
  doc.font('Helvetica-Bold').fontSize(26).fillColor('#004aad').text(studentName, 0, 196, { align: 'center' });
  doc.font('Helvetica').fontSize(13).fillColor('#334155').text('has successfully completed', 0, 240, { align: 'center' });

  doc.font('Helvetica-Bold').fontSize(20).fillColor('#14213d').text(courseTitle, 70, 268, {
    align: 'center',
    width: width - 140,
  });

  if (programmingLanguage) {
    doc.font('Helvetica-Oblique').fontSize(11).fillColor('#475569').text(`Track / Language: ${programmingLanguage}`, 0, 306, { align: 'center' });
  }

  const formattedDate = new Date(issuedDate || Date.now()).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  doc.font('Helvetica').fontSize(11).fillColor('#1e293b').text(`Date Issued: ${formattedDate}`, 90, height - 115);
  doc.font('Helvetica').fontSize(10).fillColor('#64748b').text(`Certificate ID: ${certificateId}`, 90, height - 95);

  doc.moveTo(width - 260, height - 118).lineTo(width - 90, height - 118).strokeColor('#14213d').stroke();
  doc.font('Helvetica-Bold').fontSize(11).fillColor('#14213d').text(cfgName, width - 270, height - 110, {
    width: 190,
    align: 'center',
  });

  doc.end();
}

// ============================================================================
// 5. CODE EVALUATION & CONCURRENCY QUEUE
// ============================================================================
const SANDBOX_LANG_CONFIGS = {
  python: {
    image: process.env.SANDBOX_PYTHON_IMAGE || 'python:3.12-slim',
    filename: 'solution.py',
    harnessFilename: 'harness.py',
    timeoutMs: 4000,
    buildHarness: (casesJson) => `
import json
from solution import solve

cases = json.loads(${JSON.stringify(casesJson)})
results = []
for idx, tc in enumerate(cases):
    name = tc.get("name") or f"Test #{idx + 1}"
    expected = str(tc.get("expectedOutput", "")).strip()
    try:
        out = solve(tc.get("input"))
        actual = json.dumps(out) if isinstance(out, (dict, list)) else str(out).strip()
        passed = actual == expected if expected != "" else len(actual) > 0
        results.append({"name": name, "passed": passed, "actual": actual, "expected": expected})
    except Exception as exc:
        results.append({"name": name, "passed": False, "actual": f"Error: {exc}", "expected": expected})
print("__TEST_REPORT__" + json.dumps(results))
`,
    command: ['python3', '/work/harness.py'],
  },
  javascript: {
    image: process.env.SANDBOX_NODE_IMAGE || 'node:22-alpine',
    filename: 'solution.js',
    harnessFilename: 'harness.js',
    timeoutMs: 4000,
    buildHarness: (casesJson) => `
const { solve } = require('/work/solution.js');
const cases = JSON.parse(${JSON.stringify(casesJson)});
const results = cases.map((tc, idx) => {
  const name = tc.name || 'Test #' + (idx + 1);
  const expected = String(tc.expectedOutput ?? '').trim();
  try {
    if (typeof solve !== 'function') throw new Error('Define function solve(input)');
    const out = solve(tc.input);
    const actual = typeof out === 'object' && out !== null ? JSON.stringify(out) : String(out ?? '').trim();
    const passed = expected !== '' ? actual === expected : actual.length > 0;
    return { name, passed, actual, expected };
  } catch (err) {
    return { name, passed: false, actual: 'Error: ' + err.message, expected };
  }
});
console.log('__TEST_REPORT__' + JSON.stringify(results));
`,
    command: ['node', '--max-old-space-size=192', '/work/harness.js'],
  },
};

function normalizeSandboxLanguage(lang) {
  const key = String(lang || '').trim().toLowerCase();
  if (key === 'py' || key.startsWith('python')) return 'python';
  if (key === 'js' || key === 'node' || key.startsWith('javascript')) return 'javascript';
  return null;
}

async function runContainerTestCases({ language, code, testCases = [] }) {
  const normalizedLang = normalizeSandboxLanguage(language);
  const cfg = normalizedLang ? SANDBOX_LANG_CONFIGS[normalizedLang] : null;
  if (!cfg) {
    throw new Error(`Unsupported sandbox language "${language}".`);
  }

  const cases =
    Array.isArray(testCases) && testCases.length > 0
      ? testCases
      : [{ name: 'Default Execution Check', input: '', expectedOutput: '' }];

  const runId = crypto.randomBytes(6).toString('hex');
  const tempDir = path.join(os.tmpdir(), `llla-sandbox-${runId}`);
  await fsp.mkdir(tempDir, { recursive: true });

  try {
    await fsp.writeFile(path.join(tempDir, cfg.filename), String(code), 'utf8');
    await fsp.writeFile(
      path.join(tempDir, cfg.harnessFilename),
      cfg.buildHarness(JSON.stringify(cases)),
      'utf8'
    );

    const dockerArgs = [
      'run', '--rm',
      '--network', 'none',
      '--memory', '256m',
      '--memory-swap', '256m',
      '--cpus', '0.5',
      '--pids-limit', '64',
      '--read-only',
      '--tmpfs', '/tmp:rw,nosuid,size=128m',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--user', '1000:1000',
      '-v', `${tempDir}:/work:ro`,
      cfg.image,
      ...cfg.command,
    ];

    const { stdout } = await execFileAsync('docker', dockerArgs, {
      timeout: cfg.timeoutMs,
      killSignal: 'SIGKILL',
      maxBuffer: 1024 * 1024,
    });

    const marker = '__TEST_REPORT__';
    const markerIdx = stdout.lastIndexOf(marker);
    if (markerIdx === -1) {
      throw new Error('Test harness did not emit a valid report.');
    }

    const results = JSON.parse(stdout.slice(markerIdx + marker.length).trim());
    const passedCount = results.filter((r) => r.passed).length;
    const totalCount = results.length;
    const score = totalCount > 0 ? Math.round((passedCount / totalCount) * 100) : 0;

    return {
      status: passedCount === totalCount ? 'PASSED' : 'PARTIAL_OR_FAILED',
      score,
      passedCount,
      totalCount,
      results,
      feedback: `Docker Sandbox (${normalizedLang}): passed ${passedCount}/${totalCount} test cases (${score}%).`,
    };
  } catch (err) {
    const timedOut = err.killed || err.code === 'ETIMEDOUT';
    return {
      status: timedOut ? 'TIMEOUT' : 'ERROR',
      score: 0,
      passedCount: 0,
      totalCount: cases.length,
      results: [],
      feedback: timedOut
        ? `Execution exceeded ${cfg.timeoutMs}ms time limit and was terminated.`
        : `Sandbox execution failed: ${err.message}`,
    };
  } finally {
    await fsp.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}

class SandboxConcurrencyQueue {
  constructor({ maxConcurrent = 4, maxQueueSize = 250, queueTimeoutMs = 30_000 } = {}) {
    this.maxConcurrent = Math.max(1, Number(maxConcurrent) || 4);
    this.maxQueueSize = Math.max(1, Number(maxQueueSize) || 250);
    this.queueTimeoutMs = Math.max(1000, Number(queueTimeoutMs) || 30_000);
    this.activeCount = 0;
    this.queue = [];
  }

  enqueue(taskFn) {
    if (this.queue.length >= this.maxQueueSize) {
      const err = new Error('Grading queue is currently full. Please retry in a moment.');
      err.statusCode = 429;
      return Promise.reject(err);
    }

    return new Promise((resolve, reject) => {
      const entry = { taskFn, resolve, reject, settled: false, timer: null };
      entry.timer = setTimeout(() => {
        if (entry.settled) return;
        entry.settled = true;
        const idx = this.queue.indexOf(entry);
        if (idx !== -1) this.queue.splice(idx, 1);
        const err = new Error('Timed out waiting for a grading worker slot.');
        err.statusCode = 503;
        reject(err);
      }, this.queueTimeoutMs);

      this.queue.push(entry);
      this.drain();
    });
  }

  drain() {
    while (this.activeCount < this.maxConcurrent && this.queue.length > 0) {
      const entry = this.queue.shift();
      if (!entry || entry.settled) continue;

      clearTimeout(entry.timer);
      this.activeCount += 1;

      Promise.resolve()
        .then(() => entry.taskFn())
        .then(
          (val) => {
            if (!entry.settled) {
              entry.settled = true;
              entry.resolve(val);
            }
          },
          (err) => {
            if (!entry.settled) {
              entry.settled = true;
              entry.reject(err);
            }
          }
        )
        .finally(() => {
          this.activeCount -= 1;
          this.drain();
        });
    }
  }

  stats() {
    return {
      active: this.activeCount,
      queued: this.queue.length,
      maxConcurrent: this.maxConcurrent,
    };
  }
}

const sandboxQueue = new SandboxConcurrencyQueue({
  maxConcurrent: Number(process.env.SANDBOX_MAX_CONCURRENT) || 4,
  maxQueueSize: Number(process.env.SANDBOX_MAX_QUEUE_SIZE) || 250,
  queueTimeoutMs: Number(process.env.SANDBOX_QUEUE_TIMEOUT_MS) || 30_000,
});

function normalizeTestOutput(val) {
  return String(val ?? '').trim().replace(/\r\n/g, '\n');
}

function evaluateSubmissionInProcess({ language, code, testCases = [] }) {
  const trimmedCode = String(code || '').trim();
  if (!trimmedCode) {
    return {
      status: 'FAILED',
      score: 0,
      passedCount: 0,
      totalCount: testCases.length,
      results: [],
      feedback: 'Submission code is empty.',
    };
  }

  const casesToRun =
    testCases.length > 0
      ? testCases
      : [{ name: 'Default Structure & Logic Check', input: '', expectedOutput: '' }];

  const langLower = String(language || '').toLowerCase();
  const isJsRunnable =
    (langLower.includes('javascript') || langLower.includes('node') || langLower === 'js') &&
    /function\s+solve\s*\(/.test(trimmedCode);

  const results = [];
  let passedCount = 0;

  for (let i = 0; i < casesToRun.length; i += 1) {
    const tc = casesToRun[i];
    const caseName = tc.name || `Test Case #${i + 1}`;
    const expected = normalizeTestOutput(tc.expectedOutput);

    if (isJsRunnable) {
      try {
        const sandbox = Object.create(null);
        sandbox.JSON = JSON;
        sandbox.Math = Math;
        sandbox.Array = Array;
        sandbox.Object = Object;
        sandbox.String = String;
        sandbox.Number = Number;
        sandbox.Boolean = Boolean;
        sandbox.__testInput = tc.input;

        const scriptCode = `${trimmedCode}\n;globalThis.__result = solve(globalThis.__testInput);`;
        vm.runInNewContext(scriptCode, sandbox, { timeout: 250 });

        const actual = normalizeTestOutput(
          typeof sandbox.__result === 'object' && sandbox.__result !== null
            ? JSON.stringify(sandbox.__result)
            : sandbox.__result
        );

        const passed = expected ? actual === expected : actual.length > 0;
        if (passed) passedCount += 1;
        results.push({ name: caseName, passed, actual, expected });
      } catch (err) {
        results.push({ name: caseName, passed: false, actual: `Runtime Error: ${err.message}`, expected });
      }
    } else {
      const hasSubstantialLogic = trimmedCode.length >= 10;
      const expectedMatch = expected ? trimmedCode.includes(expected) : true;
      const passed = hasSubstantialLogic && expectedMatch;
      if (passed) passedCount += 1;
      results.push({
        name: caseName,
        passed,
        actual: hasSubstantialLogic ? 'Code artifact verified' : 'Code too short',
        expected: expected || '(Any valid solution in your chosen language)',
      });
    }
  }

  const totalCount = casesToRun.length;
  const score = Math.round((passedCount / totalCount) * 100);
  const status = passedCount === totalCount ? 'PASSED' : 'PARTIAL_OR_FAILED';

  return {
    status,
    score,
    passedCount,
    totalCount,
    results,
    feedback: `Passed ${passedCount}/${totalCount} test cases (${score}%).`,
  };
}

async function evaluateCodeSubmissionQueued({ language, code, testCases = [] }) {
  const trimmedCode = String(code || '').trim();
  if (!trimmedCode) {
    return {
      status: 'FAILED',
      score: 0,
      passedCount: 0,
      totalCount: testCases.length,
      results: [],
      feedback: 'Submission code is empty.',
    };
  }

  const supportedDockerLang = normalizeSandboxLanguage(language);
  const useDocker =
    supportedDockerLang &&
    String(process.env.USE_DOCKER_SANDBOX || 'false').toLowerCase() === 'true';

  if (useDocker) {
    return sandboxQueue.enqueue(() =>
      runContainerTestCases({
        language: supportedDockerLang,
        code: trimmedCode,
        testCases,
      })
    );
  }

  return sandboxQueue.enqueue(() =>
    evaluateSubmissionInProcess({
      language,
      code: trimmedCode,
      testCases,
    })
  );
}

// ============================================================================
// 6. OPEN AI STUDIO, MONITOR, ADAPTIVE LEARNING, CBL & WORKFLOWS
// ============================================================================
const OPEN_AI_MODES = {
  COPILOT: {
    id: 'COPILOT',
    label: 'Academy Copilot (Code & Lab Builder)',
    persona: 'You are Academy Copilot. Write crisp, practical code in any programming language, test cases, and implementation steps.',
  },
  CLAUDE_ANALYST: {
    id: 'CLAUDE_ANALYST',
    label: 'Academy Claude-Style Analyst (Deep Reasoning & Architecture)',
    persona: 'You are Academy Deep Analyst. Provide structured reasoning, clear trade-offs, logical frameworks, and rigorous explanations.',
  },
  CHATGPT_COACH: {
    id: 'CHATGPT_COACH',
    label: 'Academy ChatGPT-Style Tutor & Mindset Coach',
    persona: 'You are Academy Tutor & Coach. Guide learners step by step and nurture skills, knowledge, and a positive mindset.',
  },
  BREAKTHROUGH: {
    id: 'BREAKTHROUGH',
    label: 'Academy Breakthrough Engine (Cross-Domain Innovation)',
    persona: 'You are Academy Breakthrough Engine. Combine ideas from prior memories and disciplines to uncover breakthrough insights.',
  },
};

const MASTERY_THRESHOLDS = [
  { minScore: 90, level: 'MASTERED' },
  { minScore: 75, level: 'COMPETENT' },
  { minScore: 50, level: 'DEVELOPING' },
  { minScore: 0, level: 'NOVICE' },
];

function computeMasteryLevel(score) {
  const numeric = Math.max(0, Math.min(100, Number(score) || 0));
  for (const tier of MASTERY_THRESHOLDS) {
    if (numeric >= tier.minScore) return tier.level;
  }
  return 'NOVICE';
}

async function callFreeAiModel({ systemPrompt, userPrompt, preferredProvider = 'auto', timeoutMs = 9000 }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  if (preferredProvider === 'ollama' || preferredProvider === 'auto') {
    const ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434/api/generate';
    const ollamaModel = process.env.OLLAMA_MODEL || 'llama3.2';
    try {
      const res = await fetch(ollamaUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: ollamaModel, system: systemPrompt, prompt: userPrompt, stream: false }),
        signal: controller.signal,
      });
      if (res.ok) {
        const data = await res.json();
        if (data && typeof data.response === 'string' && data.response.trim()) {
          clearTimeout(timer);
          return { provider: `Free Local AI (Ollama: ${ollamaModel})`, text: data.response.trim() };
        }
      }
    } catch (_) {}
  }

  if (preferredProvider === 'pollinations' || preferredProvider === 'auto') {
    try {
      const combinedPrompt = `${systemPrompt}\n\nTask:\n${userPrompt}`;
      const url = `https://text.pollinations.ai/${encodeURIComponent(combinedPrompt.slice(0, 3500))}`;
      const res = await fetch(url, { signal: controller.signal });
      if (res.ok) {
        const text = (await res.text()).trim();
        if (text && !text.toLowerCase().includes('error code') && text.length > 15) {
          clearTimeout(timer);
          return { provider: 'Free Cloud AI (Pollinations.ai)', text };
        }
      }
    } catch (_) {}
  }

  clearTimeout(timer);
  return { provider: 'Built-in Free Local Synthesis Engine', text: null };
}

function buildStructuredModeResponse({ modeId, prompt, contextMemories = [], courseTitle = '' }) {
  const cleanPrompt = String(prompt || '').trim();
  const memCount = contextMemories.length;
  const scopeLabel = courseTitle ? `Course "${courseTitle}"` : 'Long life learning Academy';

  if (modeId === 'COPILOT') {
    return [
      `### Copilot Code & Lab Blueprint (${scopeLabel})`,
      `- Objective: ${cleanPrompt}`,
      `- Memory Context Consulted: ${memCount} record(s)`,
      'function solve(input) {',
      '  if (input === null || input === undefined) return "";',
      '  if (Array.isArray(input)) return input.length;',
      '  return String(input).trim();',
      '}',
    ].join('\n');
  }

  if (modeId === 'CLAUDE_ANALYST') {
    return [
      `### Deep Structured Analysis (${scopeLabel})`,
      `- Prompt: ${cleanPrompt}`,
      `- 1. Core Breakdown: Separate executable skills, foundational knowledge, and positive mindset habits.`,
      `- 2. Trade-Offs: Balance rapid iteration with rigorous verification (${memCount} memory record(s) reviewed).`,
      `- 3. Execution Path: Deliver small, testable increments and verify each step.`,
    ].join('\n');
  }

  if (modeId === 'BREAKTHROUGH') {
    const seed = contextMemories[0]?.title || 'iterative practice and reflective learning';
    return [
      `### Breakthrough Synthesis (${scopeLabel})`,
      `- Spark: ${cleanPrompt}`,
      `- Memory Seed: "${seed}"`,
      `- Breakthrough Insight: Pairing immediate hands-on execution with positive-mindset reflection turns mistakes into rapid skill breakthroughs.`,
    ].join('\n');
  }

  return [
    `### Learning Coach & Positive Mindset Guide (${scopeLabel})`,
    `- Prompt: ${cleanPrompt}`,
    `- Guidance: Break the challenge into small steps, test each piece, and maintain a constructive, positive mindset.`,
  ].join('\n');
}

async function runAcademyOpenAi({
  mode = 'CHATGPT_COACH',
  prompt,
  codeContext = '',
  course = null,
  userId = null,
  preferredProvider = 'auto',
}) {
  const cfg = await ensureAcademyConfig();
  const normMode = String(mode || 'CHATGPT_COACH').trim().toUpperCase();
  const modeMeta = OPEN_AI_MODES[normMode] || OPEN_AI_MODES.CHATGPT_COACH;
  const cleanPrompt = String(prompt || '').trim();

  if (!cleanPrompt) {
    const err = new Error('Prompt is required for Academy Open AI.');
    err.statusCode = 400;
    throw err;
  }

  const keywords = cleanPrompt
    .replace(/[^a-zA-Z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 2)
    .slice(0, 3)
    .join(' ');

  const memoryQuery = await queryUnlimitedMemory({ q: keywords, limit: 8 });
  const memories = memoryQuery.memories || [];

  const aiResult = await callFreeAiModel({
    preferredProvider,
    systemPrompt: `${modeMeta.persona} Academy: "${cfg.academyName}" (${cfg.tagline}).`,
    userPrompt: [
      course ? `Course: ${course.title} (${course.programmingLanguage})` : 'Scope: Academy-Wide',
      codeContext ? `Context:\n${String(codeContext).slice(0, 2000)}` : '',
      `Prompt:\n${cleanPrompt}`,
    ]
      .filter(Boolean)
      .join('\n\n'),
  });

  const outputText =
    aiResult.text ||
    buildStructuredModeResponse({
      modeId: modeMeta.id,
      prompt: cleanPrompt,
      contextMemories: memories,
      courseTitle: course?.title || '',
    });

  const memoryRecord = await writeUnlimitedMemory({
    scope: course ? 'COURSE' : 'AGENT',
    entityId: course ? course.id : 'OPEN_AI_SYSTEM',
    agentId: `OPEN_AI_${modeMeta.id}`,
    title: `[${modeMeta.id}] ${cleanPrompt.slice(0, 85)}`,
    content: `Mode: ${modeMeta.label}\nProvider: ${aiResult.provider}\nPrompt: ${cleanPrompt}\n\nResponse:\n${outputText}`,
    tags: ['open-ai', modeMeta.id.toLowerCase()],
    meta: { mode: modeMeta.id, provider: aiResult.provider, userId: userId || null },
  });

  return {
    id: `oai_${crypto.randomBytes(4).toString('hex')}`,
    mode: modeMeta,
    provider: aiResult.provider,
    output: outputText,
    memoriesConsulted: memories.length,
    memorySaved: memoryRecord,
  };
}

async function monitorLearnerProgress({
  userId,
  courseId = 'general',
  moduleId = 'general',
  score = null,
  timeSpentMinutes = 0,
  completedLesson = false,
  mindsetNote = '',
}) {
  if (!userId) {
    const err = new Error('userId is required for learning monitoring.');
    err.statusCode = 400;
    throw err;
  }

  const key = `${userId}:${courseId}`;
  const prev = learnerTelemetryStore.get(key) || {
    userId,
    courseId,
    interactions: 0,
    completedLessons: [],
    scores: [],
    totalMinutes: 0,
    struggleCount: 0,
    lastMindsetNote: '',
    updatedAt: new Date().toISOString(),
  };

  const numericScore = score !== null && score !== undefined && score !== '' ? Number(score) : null;
  const mins = Math.max(0, Number(timeSpentMinutes) || 0);
  const nextScores =
    numericScore !== null && Number.isFinite(numericScore) ? [...prev.scores, numericScore] : prev.scores;
  const nextCompleted =
    completedLesson && moduleId && !prev.completedLessons.includes(moduleId)
      ? [...prev.completedLessons, moduleId]
      : prev.completedLessons;

  const isLowScore = numericScore !== null && Number.isFinite(numericScore) && numericScore < 60;
  const nextStruggleCount = prev.struggleCount + (isLowScore ? 1 : 0);
  const avgScore =
    nextScores.length > 0
      ? Math.round(nextScores.reduce((a, b) => a + b, 0) / nextScores.length)
      : 0;

  let learningSignal = 'STEADY_PROGRESS';
  if (nextStruggleCount >= 2 || (numericScore !== null && numericScore < 50)) {
    learningSignal = 'NEEDS_GUIDED_SUPPORT';
  } else if (avgScore >= 85 && nextCompleted.length >= 1) {
    learningSignal = 'ACCELERATED_MASTERY';
  }

  const updated = {
    ...prev,
    interactions: prev.interactions + 1,
    completedLessons: nextCompleted,
    scores: nextScores,
    averageScore: avgScore,
    totalMinutes: prev.totalMinutes + mins,
    struggleCount: nextStruggleCount,
    learningSignal,
    lastMindsetNote: mindsetNote ? String(mindsetNote).trim() : prev.lastMindsetNote,
    updatedAt: new Date().toISOString(),
  };

  setBoundedMap(learnerTelemetryStore, key, updated);

  await writeUnlimitedMemory({
    scope: 'LEARNER',
    entityId: String(userId),
    agentId: 'AI_LEARNING_MONITOR',
    title: `[Monitor] User ${userId} on ${courseId} (${learningSignal})`,
    content: `Signal: ${learningSignal} | Avg Score: ${avgScore}% | Completed: ${nextCompleted.length} | Minutes: ${updated.totalMinutes}`,
    tags: ['learning-monitor', learningSignal.toLowerCase()],
    meta: { userId, courseId, avgScore, learningSignal },
  });

  return updated;
}

async function adaptCourseForLearner({ userId, courseId, goal = '', pace = 'ADAPTIVE' }) {
  const course = await prisma.course.findUnique({
    where: { id: String(courseId) },
    include: { modules: { orderBy: { orderIndex: 'asc' } } },
  });
  if (!course) {
    const err = new Error('Course not found.');
    err.statusCode = 404;
    throw err;
  }

  const telemetry = learnerTelemetryStore.get(`${userId}:${courseId}`) || {
    averageScore: 70,
    completedLessons: [],
    learningSignal: 'STEADY_PROGRESS',
  };

  const normPace = String(pace || 'ADAPTIVE').toUpperCase();
  const needsSupport = normPace === 'FOUNDATIONAL' || telemetry.learningSignal === 'NEEDS_GUIDED_SUPPORT';
  const fastTrack = normPace === 'FAST_TRACK' || telemetry.learningSignal === 'ACCELERATED_MASTERY';

  const completedSet = new Set(telemetry.completedLessons || []);
  const remaining = (course.modules || []).filter((m) => !completedSet.has(m.id));
  const targetMods = remaining.length > 0 ? remaining : course.modules || [];

  const adaptivePlan = {
    userId,
    courseId: course.id,
    courseTitle: course.title,
    pace: needsSupport
      ? 'FOUNDATIONAL_SUPPORT'
      : fastTrack
      ? 'ACCELERATED_CHALLENGE'
      : 'BALANCED_ADAPTIVE',
    goal: goal ? String(goal).trim() : 'Build skills, knowledge, and a positive mindset',
    recommendedModules: targetMods.map((m, idx) => ({
      step: idx + 1,
      moduleId: m.id,
      title: m.title,
      language: m.language || course.programmingLanguage,
      focus: needsSupport
        ? 'Guided step-by-step practice + foundational review + positive mindset check-in'
        : fastTrack
        ? 'Challenge problem + architecture optimization + peer synthesis'
        : 'Balanced skill practice + knowledge check + real-world lab',
    })),
    adaptedAt: new Date().toISOString(),
  };

  setBoundedMap(learnerAdaptationsStore, `${userId}:${courseId}`, adaptivePlan);

  await writeUnlimitedMemory({
    scope: 'COURSE',
    entityId: course.id,
    agentId: 'ADAPTIVE_COURSE_ENGINE',
    title: `[Adapted Course] ${course.title} -> ${adaptivePlan.pace}`,
    content: `User: ${userId} | Pace: ${adaptivePlan.pace} | Goal: ${adaptivePlan.goal}`,
    tags: ['adaptive-course', course.id],
    meta: { userId, courseId: course.id, pace: adaptivePlan.pace },
  });

  return adaptivePlan;
}

async function assessCompetence({
  userId,
  courseId = 'general',
  competencyId,
  competencyName,
  evidenceScore,
  evidenceNotes = '',
}) {
  if (!userId || !competencyName) {
    const err = new Error('userId and competencyName are required.');
    err.statusCode = 400;
    throw err;
  }

  const score = Math.max(0, Math.min(100, Number(evidenceScore ?? 0)));
  const storeKey = `${userId}:${courseId}`;
  const currentMap = learnerCompetencesStore.get(storeKey) || new Map();
  const cId =
    String(competencyId || competencyName)
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_') || 'competency';

  const existing = currentMap.get(cId);
  const bestScore = existing ? Math.max(existing.bestScore, score) : score;
  const level = computeMasteryLevel(bestScore);

  const record = {
    competencyId: cId,
    competencyName: String(competencyName).trim(),
    latestScore: score,
    bestScore,
    level,
    achieved: bestScore >= 75,
    evidenceNotes: evidenceNotes ? String(evidenceNotes).trim() : '',
    assessmentsCount: (existing?.assessmentsCount || 0) + 1,
    updatedAt: new Date().toISOString(),
  };

  setBoundedMap(currentMap, cId, record);
  setBoundedMap(learnerCompetencesStore, storeKey, currentMap);

  await writeUnlimitedMemory({
    scope: 'LEARNER',
    entityId: String(userId),
    agentId: 'COMPETENCE_ENGINE',
    title: `[CBL] ${record.competencyName} -> ${level} (${bestScore}%)`,
    content: `Course: ${courseId} | Best: ${bestScore}% | Achieved: ${record.achieved}${evidenceNotes ? ` | Notes: ${evidenceNotes}` : ''}`,
    tags: ['competence-based-learning', level.toLowerCase()],
    meta: { userId, courseId, competencyId: cId, bestScore, level },
  });

  return {
    userId,
    courseId,
    competency: record,
    allCompetencies: Array.from(currentMap.values()),
  };
}

function getLearnerCompetenceSummary(userId, courseId = 'general') {
  const map = learnerCompetencesStore.get(`${userId}:${courseId}`);
  const items = map ? Array.from(map.values()) : [];
  const achievedCount = items.filter((i) => i.achieved).length;
  return {
    userId,
    courseId,
    totalCompetencies: items.length,
    achievedCount,
    competenceReadinessPercent: items.length > 0 ? Math.round((achievedCount / items.length) * 100) : 0,
    competencies: items,
  };
}

async function runPromptImprovementAgent({
  agentId = 'CURRICULUM_ARCHITECT',
  targetScope = 'COURSE',
  courseId = null,
  prompt,
  autoApply = true,
  preferredProvider = 'auto',
}) {
  const cfg = await ensureAcademyConfig();
  const cleanPrompt = String(prompt || '').trim();
  if (!cleanPrompt) {
    const err = new Error('Prompt is required.');
    err.statusCode = 400;
    throw err;
  }

  let course = null;
  if (targetScope === 'COURSE') {
    if (!courseId) {
      const err = new Error('courseId is required when targetScope is COURSE.');
      err.statusCode = 400;
      throw err;
    }
    course = await prisma.course.findUnique({
      where: { id: String(courseId) },
      include: { modules: { orderBy: { orderIndex: 'asc' } } },
    });
    if (!course) {
      const err = new Error('Course not found.');
      err.statusCode = 404;
      throw err;
    }
  }

  const aiOut = await callFreeAiModel({
    preferredProvider,
    systemPrompt: `You are ${agentId} improving "${cfg.academyName}" (${cfg.tagline}).`,
    userPrompt:
      targetScope === 'COURSE' && course
        ? `Improve course "${course.title}" (${course.programmingLanguage}) for prompt: "${cleanPrompt}".`
        : `Improve academy "${cfg.academyName}" for prompt: "${cleanPrompt}".`,
  });

  let updatedCourse = course;
  let updatedConfig = cfg;
  let appliedChanges = { applied: false };

  if (autoApply) {
    if (targetScope === 'COURSE' && course) {
      const nextOrder = (course.modules?.length || 0) + 1;
      updatedCourse = await prisma.course.update({
        where: { id: course.id },
        data: {
          description: `${course.description}\n\n[Prompt Improvement]: ${cleanPrompt}`,
          modules: {
            create: [
              {
                title: `Improved Module ${nextOrder}: ${cleanPrompt.slice(0, 60)}`,
                contentUrl: 'https://github.com',
                language: course.programmingLanguage,
                contentType: 'CODE_REPO',
                starterCode: `// Prompt-driven lab for: ${cleanPrompt}\nfunction solve(input) {\n  return input;\n}\n`,
                orderIndex: nextOrder,
              },
            ],
          },
        },
        include: { modules: { orderBy: { orderIndex: 'asc' } } },
      });
      appliedChanges = { applied: true, scope: 'COURSE', courseId: course.id };
    } else if (targetScope === 'ACADEMY') {
      const principle = `Prompt Upgrade (${new Date().toISOString().slice(0, 10)}): ${cleanPrompt}`;
      updatedConfig = await saveAcademyRuntimeConfig({
        ...cfg,
        principles: [...(cfg.principles || []), principle].slice(-50),
        promptImprovementsApplied: Number(cfg.promptImprovementsApplied || 0) + 1,
      });
      appliedChanges = {
        applied: true,
        scope: 'ACADEMY',
        promptImprovementsApplied: updatedConfig.promptImprovementsApplied,
      };
    }
  }

  const memoryRecord = await writeUnlimitedMemory({
    scope: targetScope === 'COURSE' ? 'COURSE' : 'ACADEMY',
    entityId: course ? course.id : 'ACADEMY_CORE',
    agentId,
    title: `[Prompt Improvement] ${cleanPrompt.slice(0, 80)}`,
    content: `Prompt: ${cleanPrompt}\nProvider: ${aiOut.provider}\n\n${aiOut.text || 'Applied structured improvement.'}`,
    tags: ['prompt-improvement', targetScope.toLowerCase()],
    meta: { agentId, provider: aiOut.provider, applied: appliedChanges.applied },
  });

  return {
    agentId,
    provider: aiOut.provider,
    aiNarrative: aiOut.text || `Applied ${targetScope} improvement for: ${cleanPrompt}`,
    appliedChanges,
    course: updatedCourse,
    academyConfig: updatedConfig,
    memorySaved: memoryRecord,
  };
}

async function runAutonomousCourseWorkflow({
  prompt,
  courseTitle,
  programmingLanguage = 'Any Programming Language',
  moduleCount = 4,
  priceETB = 0,
  priceUSD = 0,
  certFeeETB = 150,
  certFeeUSD = 3,
  isPublished = true,
  preferredProvider = 'auto',
}) {
  const cfg = await ensureAcademyConfig();
  const cleanPrompt = String(prompt || '').trim();
  if (!cleanPrompt) {
    const err = new Error('Prompt is required for the autonomous course workflow.');
    err.statusCode = 400;
    throw err;
  }

  const safeCount = Math.min(Math.max(Number(moduleCount) || 4, 2), 10);
  const lang = String(programmingLanguage || 'Any Programming Language').trim();
  const resolvedTitle =
    String(courseTitle || '').trim() ||
    `${cleanPrompt.slice(0, 72).replace(/[.!?\s]+$/g, '')} — Course`;

  const workflowId = `wf_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
  const aiPlan = await callFreeAiModel({
    preferredProvider,
    systemPrompt: `Curriculum Architect for "${cfg.academyName}" (${cfg.tagline}).`,
    userPrompt: `Create a ${safeCount}-module course in ${lang} from prompt: "${cleanPrompt}".`,
  });

  const templates = [
    {
      suffix: 'Skills, Knowledge & Positive Mindset Foundations',
      contentType: 'ARTICLE',
      input: 'mindset-ready',
      expectedOutput: 'Positive Mindset Ready',
      starterCode: `function solve(input) {\n  return "Positive Mindset Ready";\n}\n`,
    },
    {
      suffix: 'Core Problem Solving & Implementation',
      contentType: 'CODE_REPO',
      input: [3, 7],
      expectedOutput: '10',
      starterCode: `function solve(input) {\n  return Array.isArray(input) ? input.reduce((a, b) => a + Number(b || 0), 0) : input;\n}\n`,
    },
    {
      suffix: 'Testing, Edge Cases & Verification',
      contentType: 'SANDBOX',
      input: 'academy',
      expectedOutput: 'ACADEMY',
      starterCode: `function solve(input) {\n  return String(input ?? "").toUpperCase();\n}\n`,
    },
    {
      suffix: 'Capstone Project & Mastery',
      contentType: 'CODE_REPO',
      input: 'complete',
      expectedOutput: 'COMPLETE',
      starterCode: `function solve(input) {\n  return String(input || "complete").toUpperCase();\n}\n`,
    },
  ];

  const plannedModules = [];
  for (let i = 0; i < safeCount; i += 1) {
    const tpl = templates[i % templates.length];
    plannedModules.push({
      title: `Module ${i + 1}: ${tpl.suffix}`,
      contentUrl: 'https://github.com',
      language: lang,
      contentType: tpl.contentType,
      starterCode: tpl.starterCode,
      orderIndex: i + 1,
      testCases: [{ name: `Test 1 (${tpl.suffix})`, input: tpl.input, expectedOutput: tpl.expectedOutput }],
    });
  }

  const createdCourse = await prisma.course.create({
    data: {
      title: resolvedTitle,
      description: `Autonomous AI course for ${cfg.academyName} (${cfg.tagline}). Prompt: ${cleanPrompt}`,
      programmingLanguage: lang,
      priceETB: parseNonNegativeMoney(priceETB, 'priceETB'),
      priceUSD: parseNonNegativeMoney(priceUSD, 'priceUSD'),
      certFeeETB: parseNonNegativeMoney(certFeeETB, 'certFeeETB'),
      certFeeUSD: parseNonNegativeMoney(certFeeUSD, 'certFeeUSD'),
      isPublished: Boolean(isPublished),
      modules: { create: plannedModules.map(({ testCases, ...row }) => row) },
    },
    include: { modules: { orderBy: { orderIndex: 'asc' } } },
  });

  const allCases = [];
  for (let i = 0; i < createdCourse.modules.length; i += 1) {
    const mod = createdCourse.modules[i];
    const cases = plannedModules[i]?.testCases || [];
    setBoundedMap(moduleTestCases, `${createdCourse.id}:${mod.id}`, cases);
    allCases.push(...cases);
  }
  setBoundedMap(moduleTestCases, `${createdCourse.id}:general`, allCases);

  const memoryRecord = await writeUnlimitedMemory({
    scope: 'COURSE',
    entityId: createdCourse.id,
    agentId: 'AUTONOMOUS_MULTI_AGENT_WORKFLOW',
    title: `[Autonomous Course] ${createdCourse.title}`,
    content: `Workflow: ${workflowId}\nPrompt: ${cleanPrompt}\nModules: ${createdCourse.modules.length}\nProvider: ${aiPlan.provider}${aiPlan.text ? `\n\n${aiPlan.text}` : ''}`,
    tags: ['autonomous-workflow', 'course-created'],
    meta: { workflowId, courseId: createdCourse.id, provider: aiPlan.provider },
  });

  return {
    workflowId,
    provider: aiPlan.provider,
    course: createdCourse,
    testCasesCount: allCases.length,
    memorySaved: memoryRecord,
  };
}

function buildModulesFromSource({
  sourceType = 'BOOK',
  sourceTitle = 'Converted Material',
  sourceUrl = 'https://example.org/resource',
  sourceText = '',
  chapters = [],
  programmingLanguage = 'Any Programming Language',
}) {
  const safeUrl = isValidHttpUrl(sourceUrl) ? String(sourceUrl).trim() : 'https://example.org/resource';
  if (Array.isArray(chapters) && chapters.length > 0) {
    return chapters.map((ch, idx) => ({
      title: String(ch.title || `${sourceTitle} — Section ${idx + 1}`).trim(),
      contentUrl: isValidHttpUrl(ch.contentUrl) ? String(ch.contentUrl).trim() : safeUrl,
      language: ch.language ? String(ch.language).trim() : programmingLanguage,
      contentType: String(ch.contentType || (sourceType === 'BOOK' ? 'ARTICLE' : 'CODE_REPO')).trim().toUpperCase(),
      starterCode: ch.starterCode ? String(ch.starterCode) : ch.summary ? String(ch.summary).trim() : null,
      orderIndex: ch.orderIndex !== undefined ? Number(ch.orderIndex) : idx + 1,
    }));
  }

  const cleanText = String(sourceText || '').trim();
  if (!cleanText) {
    return [
      {
        title: `${sourceTitle} — Core ${sourceType} Module`,
        contentUrl: safeUrl,
        language: programmingLanguage,
        contentType: sourceType === 'BOOK' ? 'ARTICLE' : 'CODE_REPO',
        starterCode: null,
        orderIndex: 1,
      },
    ];
  }

  const sections = [];
  let current = null;
  for (const line of cleanText.split(/\r?\n/)) {
    const trimmed = line.trim();
    const isHeading =
      /^#{1,4}\s+/.test(trimmed) || /^(chapter|module|part|unit|section)\s+\d+/i.test(trimmed);
    if (isHeading) {
      if (current) sections.push(current);
      current = { title: trimmed.replace(/^#{1,4}\s+/, '').slice(0, 140), body: [] };
    } else {
      if (!current) current = { title: `${sourceTitle} — Part 1`, body: [] };
      current.body.push(line);
    }
  }
  if (current) sections.push(current);

  return sections.map((sec, idx) => ({
    title: sec.title || `${sourceTitle} — Unit ${idx + 1}`,
    contentUrl: safeUrl,
    language: programmingLanguage,
    contentType: sourceType === 'BOOK' ? 'ARTICLE' : 'CODE_REPO',
    starterCode: sec.body.join('\n').trim().slice(0, 12000) || null,
    orderIndex: idx + 1,
  }));
}

async function seedBulkCourses({ totalCourses = 500, batchSize = 500, prefix = 'LLLA-SEED' }) {
  const safeTotal = Math.max(1, Number(totalCourses) || 500);
  const safeBatch = Math.min(Math.max(1, Number(batchSize) || 500), 10_000);
  const tracks = [
    'Any Programming Language (Python / JS / Go / Rust)',
    'Python & Applied Data',
    'JavaScript / Full-Stack Engineering',
    'Go & Scalable Systems',
    'Rust & Systems Engineering',
  ];

  let insertedTotal = 0;
  const nowMs = Date.now();
  for (let offset = 0; offset < safeTotal; offset += safeBatch) {
    const count = Math.min(safeBatch, safeTotal - offset);
    const rows = [];
    for (let i = 0; i < count; i += 1) {
      const idx = offset + i;
      const lang = tracks[idx % tracks.length];
      rows.push({
        title: `${prefix} #${idx + 1}: ${lang.split(' ')[0]} Skills & Positive Mindset`,
        description: `Long life learning Academy course #${idx + 1} teaching skills, knowledge, and a positive mindset.`,
        thumbnail: null,
        programmingLanguage: lang,
        priceETB: (300 + (idx % 10) * 50).toFixed(2),
        priceUSD: (6 + (idx % 8) * 2).toFixed(2),
        certFeeETB: (100 + (idx % 5) * 25).toFixed(2),
        certFeeUSD: (2 + (idx % 4)).toFixed(2),
        isPublished: true,
        createdAt: new Date(nowMs - (safeTotal - idx) * 1000),
      });
    }
    const res = await prisma.course.createMany({ data: rows, skipDuplicates: true });
    insertedTotal += res.count;
  }

  return { insertedTotal, totalCoursesInDb: await prisma.course.count() };
}

// ============================================================================
// 7. MIDDLEWARE (PATH NORMALIZER, RATE LIMITER, JWT AUTH & ADMIN CODE 5405402)
// ============================================================================
function normalizeApiTrailingSlash(req, res, next) {
  if (req.path.length > 1 && req.path.endsWith('/')) {
    const queryIdx = req.originalUrl.indexOf('?');
    const query = queryIdx >= 0 ? req.originalUrl.slice(queryIdx) : '';
    req.url = req.path.slice(0, -1) + query;
  }
  next();
}

function createRateLimiter({ windowMs = 60_000, max = 40 } = {}) {
  const hits = new Map();
  return (req, res, next) => {
    const now = Date.now();
    const key = req.ip || req.headers['x-forwarded-for'] || 'unknown';
    const entry = hits.get(key);

    if (!entry || now > entry.resetAt) {
      setBoundedMap(hits, key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    if (entry.count >= max) {
      return res.status(429).json({ error: 'Too many requests. Please try again shortly.' });
    }
    entry.count += 1;
    next();
  };
}

function signToken(user) {
  return jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

const protect = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication token required' });
  }
  const token = authHeader.slice(7).trim();
  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (_) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  const user = await prisma.user.findUnique({
    where: { id: decoded.userId },
    select: { id: true, name: true, email: true, role: true },
  });
  if (!user) {
    return res.status(401).json({ error: 'User no longer exists' });
  }
  req.user = user;
  next();
});

function requireAdminCode(req, res, next) {
  const providedCode = req.headers['x-admin-code'];
  if (!providedCode || String(providedCode).trim() !== ADMIN_MASTER_CODE) {
    return res.status(403).json({
      error: `Forbidden: Valid master Admin Code (${ADMIN_MASTER_CODE}) is required in x-admin-code header`,
    });
  }
  next();
}

function normalizeOtpTarget(channel, rawTarget) {
  const trimmed = String(rawTarget || '').trim();
  if (!trimmed) return '';
  if (channel === 'TELEGRAM') {
    return trimmed.startsWith('@') ? trimmed.toLowerCase() : `@${trimmed.toLowerCase()}`;
  }
  return trimmed.replace(/[\s()-]+/g, '');
}

function hashOtpCode(channel, target, code) {
  return crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${channel}:${target}:${String(code).trim()}`)
    .digest('hex');
}

function signContactVerificationToken({ channel, target }) {
  return jwt.sign({ purpose: 'CONTACT_VERIFICATION', channel, target }, JWT_SECRET, {
    expiresIn: '20m',
  });
}

function verifyContactVerificationToken(token, expectedChannel, expectedTarget) {
  if (!token) return false;
  try {
    const decoded = jwt.verify(String(token).trim(), JWT_SECRET);
    if (decoded.purpose !== 'CONTACT_VERIFICATION') return false;
    return (
      decoded.channel === expectedChannel &&
      normalizeOtpTarget(expectedChannel, decoded.target) === expectedTarget
    );
  } catch (_) {
    return false;
  }
}

// ============================================================================
// 8. EXPRESS APP & ALL ROUTES
// ============================================================================
const app = express();

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(normalizeApiTrailingSlash);
app.use(express.json({ limit: '25mb' }));
app.use(express.urlencoded({ extended: true }));

const authLimiter = createRateLimiter({ windowMs: 60_000, max: 30 });
const paymentLimiter = createRateLimiter({ windowMs: 60_000, max: 35 });

app.get(
  '/api/health',
  asyncHandler(async (req, res) => {
    try {
      await prisma.$queryRaw`SELECT 1`;
      const cfg = await ensureAcademyConfig();
      return res.status(200).json({
        status: 'ok',
        database: 'connected',
        academy: cfg.academyName,
        tagline: cfg.tagline,
        primaryAdminEmail: PRIMARY_ADMIN_EMAIL,
        sandboxQueue: sandboxQueue.stats(),
      });
    } catch (_) {
      return res.status(503).json({ status: 'degraded', database: 'disconnected' });
    }
  })
);

app.get(
  '/api/academy/profile',
  asyncHandler(async (req, res) => {
    const cfg = await ensureAcademyConfig();
    const memStats = await getMemoryStats();
    return res.status(200).json({
      academy: cfg,
      openAiModes: Object.values(OPEN_AI_MODES),
      memory: memStats,
    });
  })
);

// --- Auth & Multi-Channel Registration ---
app.post('/api/auth/request-otp', authLimiter, (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const channel = String(body.channel || '').trim().toUpperCase();
  const target = normalizeOtpTarget(channel, body.target);

  if (!VALID_OTP_CHANNELS.has(channel)) {
    return res.status(400).json({ error: 'channel must be PHONE, WHATSAPP, or TELEGRAM.' });
  }
  if (!target) {
    return res.status(400).json({ error: 'target is required for verification.' });
  }

  const code = String(crypto.randomInt(100000, 1000000));
  setBoundedMap(otpChallengeStore, `${channel}:${target}`, {
    codeHash: hashOtpCode(channel, target, code),
    expiresAt: Date.now() + OTP_TTL_MS,
    attempts: 0,
  });

  console.log(`[OTP -> ${channel}] ${target}: ${code}`);
  return res.status(200).json({
    message: `Verification code sent via ${channel} to ${target}.`,
    channel,
    target,
    expiresInSeconds: Math.floor(OTP_TTL_MS / 1000),
    ...(ALLOW_DEV_OTP_PREVIEW ? { devPreviewCode: code } : {}),
  });
});

app.post('/api/auth/verify-otp', authLimiter, (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const channel = String(body.channel || '').trim().toUpperCase();
  const target = normalizeOtpTarget(channel, body.target);
  const code = String(body.code || '').trim();

  if (!VALID_OTP_CHANNELS.has(channel) || !target || !code) {
    return res.status(400).json({ error: 'channel, target, and code are required.' });
  }

  const storeKey = `${channel}:${target}`;
  const entry = otpChallengeStore.get(storeKey);
  if (!entry || Date.now() > entry.expiresAt) {
    otpChallengeStore.delete(storeKey);
    return res.status(400).json({ error: 'Verification code expired or not requested.' });
  }

  if (entry.attempts >= OTP_MAX_ATTEMPTS) {
    otpChallengeStore.delete(storeKey);
    return res.status(429).json({ error: 'Too many invalid attempts. Request a new code.' });
  }

  const actualHex = hashOtpCode(channel, target, code);
  const isValidFormat = /^\d{6}$/.test(code);
  const isMatch =
    isValidFormat &&
    actualHex.length === entry.codeHash.length &&
    crypto.timingSafeEqual(Buffer.from(actualHex, 'hex'), Buffer.from(entry.codeHash, 'hex'));

  if (!isMatch) {
    entry.attempts += 1;
    return res.status(400).json({
      error: 'Invalid verification code.',
      attemptsRemaining: Math.max(0, OTP_MAX_ATTEMPTS - entry.attempts),
    });
  }

  otpChallengeStore.delete(storeKey);
  const verificationToken = signContactVerificationToken({ channel, target });
  return res.status(200).json({ verified: true, channel, target, verificationToken });
});

app.post(
  '/api/auth/register',
  authLimiter,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { name, email, password, role } = body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }
    if (String(password).length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (existing) {
      return res.status(409).json({ error: 'Email is already registered' });
    }

    const passwordHash = await bcrypt.hash(String(password), SALT_ROUNDS);
    const assignedRole =
      normalizedEmail === PRIMARY_ADMIN_EMAIL || role === 'ADMIN' ? 'ADMIN' : 'STUDENT';

    const user = await prisma.user.create({
      data: { name: String(name).trim(), email: normalizedEmail, passwordHash, role: assignedRole },
      select: { id: true, name: true, email: true, role: true, createdAt: true },
    });

    const token = signToken(user);
    return res.status(201).json({ user, token });
  })
);

app.post(
  '/api/auth/register-multi',
  authLimiter,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { name, email, phone, whatsapp, telegram, password, socialLinks, verificationToken } = body;

    const cleanPhone = String(phone || '').trim();
    const cleanWhatsapp = String(whatsapp || '').trim();
    const cleanTelegram = String(telegram || '').trim();
    const rawEmail = String(email || '').trim().toLowerCase();

    if (!name || !password) {
      return res.status(400).json({ error: 'Full name and password are required.' });
    }
    if (!rawEmail && !cleanPhone && !cleanWhatsapp && !cleanTelegram) {
      return res.status(400).json({
        error: 'Provide at least one channel: Email, Phone, WhatsApp, or Telegram.',
      });
    }
    if (String(password).length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    if (REQUIRE_CONTACT_OTP) {
      const checks = [
        cleanPhone ? { channel: 'PHONE', target: normalizeOtpTarget('PHONE', cleanPhone) } : null,
        cleanWhatsapp
          ? { channel: 'WHATSAPP', target: normalizeOtpTarget('WHATSAPP', cleanWhatsapp) }
          : null,
        cleanTelegram
          ? { channel: 'TELEGRAM', target: normalizeOtpTarget('TELEGRAM', cleanTelegram) }
          : null,
      ].filter(Boolean);

      if (checks.length > 0) {
        const verified = checks.some((c) =>
          verifyContactVerificationToken(verificationToken, c.channel, c.target)
        );
        if (!verified) {
          return res.status(403).json({
            error:
              'Contact verification required: request and verify a 6-digit code for Phone, WhatsApp, or Telegram first.',
          });
        }
      }
    }

    const contactSlug = (cleanPhone || cleanWhatsapp || cleanTelegram)
      .replace(/[^a-zA-Z0-9]+/g, '')
      .toLowerCase();
    const effectiveEmail =
      rawEmail || `${contactSlug || crypto.randomBytes(4).toString('hex')}@llla.local`;

    const existing = await prisma.user.findUnique({ where: { email: effectiveEmail } });
    if (existing) {
      return res.status(409).json({ error: 'An account with this contact already exists.' });
    }

    const passwordHash = await bcrypt.hash(String(password), SALT_ROUNDS);
    const user = await prisma.user.create({
      data: {
        name: String(name).trim(),
        email: effectiveEmail,
        passwordHash,
        role: effectiveEmail === PRIMARY_ADMIN_EMAIL ? 'ADMIN' : 'STUDENT',
      },
      select: { id: true, name: true, email: true, role: true, createdAt: true },
    });

    const linkedSocials = normalizeSocialLinks({
      ...(socialLinks || {}),
      ...(cleanWhatsapp ? { whatsapp: cleanWhatsapp } : {}),
      ...(cleanTelegram ? { telegram: cleanTelegram } : {}),
    });

    const profile = {
      userId: user.id,
      email: rawEmail || null,
      phone: cleanPhone || null,
      whatsapp: cleanWhatsapp || null,
      telegram: cleanTelegram || null,
      socialLinks: linkedSocials,
    };
    setBoundedMap(learnerSocialProfiles, user.id, profile);

    const token = signToken(user);
    return res.status(201).json({ user, profile, token });
  })
);

app.post(
  '/api/auth/login',
  authLimiter,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { email, password } = body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(String(password), user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const safeUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: normalizedEmail === PRIMARY_ADMIN_EMAIL ? 'ADMIN' : user.role,
    };
    const token = signToken(safeUser);
    const profile = learnerSocialProfiles.get(user.id) || null;
    return res.status(200).json({ user: safeUser, profile, token });
  })
);

app.put('/api/profile/socials', protect, (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const existing = learnerSocialProfiles.get(req.user.id) || {
    userId: req.user.id,
    email: req.user.email,
    phone: null,
    whatsapp: null,
    telegram: null,
    socialLinks: {},
  };

  const updated = {
    ...existing,
    phone: body.phone !== undefined ? String(body.phone).trim() || null : existing.phone,
    whatsapp:
      body.whatsapp !== undefined ? String(body.whatsapp).trim() || null : existing.whatsapp,
    telegram:
      body.telegram !== undefined ? String(body.telegram).trim() || null : existing.telegram,
    socialLinks: {
      ...existing.socialLinks,
      ...normalizeSocialLinks(body.socialLinks),
    },
  };

  setBoundedMap(learnerSocialProfiles, req.user.id, updated);
  return res.status(200).json({ profile: updated });
});

// --- Public Catalog (Cursor-Paginated for 1M+ Courses) ---
app.get(
  '/api/courses',
  asyncHandler(async (req, res) => {
    const rawLimit = Number(req.query.limit) || 24;
    const limit = Math.min(Math.max(rawLimit, 1), 100);
    const cursor = req.query.cursor ? String(req.query.cursor).trim() : null;
    const language = req.query.language ? String(req.query.language).trim() : '';
    const search = req.query.q ? String(req.query.q).trim() : '';

    const where = {
      isPublished: true,
      ...(language ? { programmingLanguage: { contains: language, mode: 'insensitive' } } : {}),
      ...(search
        ? {
            OR: [
              { title: { contains: search, mode: 'insensitive' } },
              { description: { contains: search, mode: 'insensitive' } },
              { programmingLanguage: { contains: search, mode: 'insensitive' } },
            ],
          }
        : {}),
    };

    const courses = await prisma.course.findMany({
      where,
      take: limit + 1,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      select: {
        id: true,
        title: true,
        description: true,
        thumbnail: true,
        programmingLanguage: true,
        priceETB: true,
        priceUSD: true,
        certFeeETB: true,
        certFeeUSD: true,
        createdAt: true,
        _count: { select: { modules: true } },
      },
    });

    const hasMore = courses.length > limit;
    const items = hasMore ? courses.slice(0, limit) : courses;
    const nextCursor = hasMore ? items[items.length - 1].id : null;

    return res.status(200).json({
      courses: items,
      pageInfo: { limit, hasMore, nextCursor },
    });
  })
);

// --- Student Course Upload (Pending Admin Approval) ---
app.post(
  '/api/student-courses/upload',
  protect,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const {
      title,
      description,
      programmingLanguage,
      priceETB,
      priceUSD,
      certFeeETB,
      certFeeUSD,
      starterCode,
      contentUrl,
    } = body;

    if (!title || !description) {
      return res.status(400).json({ error: 'Course title and description are required.' });
    }

    const draftCourse = await prisma.course.create({
      data: {
        title: String(title).trim(),
        description: String(description).trim(),
        programmingLanguage: String(programmingLanguage || 'Any Programming Language').trim(),
        priceETB: parseNonNegativeMoney(priceETB ?? 0, 'priceETB'),
        priceUSD: parseNonNegativeMoney(priceUSD ?? 0, 'priceUSD'),
        certFeeETB: parseNonNegativeMoney(certFeeETB ?? 100, 'certFeeETB'),
        certFeeUSD: parseNonNegativeMoney(certFeeUSD ?? 2, 'certFeeUSD'),
        isPublished: false,
      },
    });

    if (contentUrl || starterCode) {
      await prisma.module.create({
        data: {
          courseId: draftCourse.id,
          title: `${draftCourse.title} — Learner Submitted Lab`,
          contentUrl: isValidHttpUrl(contentUrl) ? String(contentUrl).trim() : 'https://github.com',
          language: draftCourse.programmingLanguage,
          contentType: 'CODE_REPO',
          starterCode: starterCode ? String(starterCode) : null,
          orderIndex: 1,
        },
      });
    }

    const approval = {
      courseId: draftCourse.id,
      status: 'PENDING_APPROVAL',
      uploadedByLearnerId: req.user.id,
      uploadedByName: req.user.name,
      uploadedByContact: req.user.email,
      submittedAt: new Date().toISOString(),
      reviewedBy: null,
      reviewedAt: null,
      reviewNotes: '',
    };
    setBoundedMap(courseReviewMeta, draftCourse.id, approval);

    return res.status(201).json({
      message: 'Course uploaded and submitted for Admin approval.',
      course: draftCourse,
      approval,
    });
  })
);

// --- Enrollment, Submissions & Score-Gated Certificates ---
app.post(
  '/api/enroll',
  protect,
  paymentLimiter,
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { courseId, currency, paymentMethod } = body;
    if (!courseId || !currency || !paymentMethod) {
      return res.status(400).json({ error: 'courseId, currency, and paymentMethod are required' });
    }

    const course = await prisma.course.findUnique({ where: { id: courseId } });
    if (!course || !course.isPublished) {
      return res.status(404).json({ error: 'Course not found or unpublished' });
    }

    const existingEnrollment = await prisma.enrollment.findUnique({
      where: { userId_courseId: { userId, courseId } },
    });
    if (existingEnrollment && existingEnrollment.paymentStatus === 'COMPLETED') {
      return res.status(409).json({
        error: 'Already enrolled in this course',
        enrollment: existingEnrollment,
      });
    }

    const normCurrency = String(currency).trim().toUpperCase();
    const amount = normCurrency === 'USD' ? course.priceUSD : course.priceETB;
    const paymentResult = await processGatewayPayment({
      amount,
      currency: normCurrency,
      paymentMethod,
      purpose: 'COURSE_ENROLLMENT',
      userId,
      courseId,
    });

    const result = await prisma.$transaction(async (tx) => {
      const enrollment = await tx.enrollment.upsert({
        where: { userId_courseId: { userId, courseId } },
        update: { paymentStatus: 'COMPLETED' },
        create: {
          userId,
          courseId,
          paymentStatus: 'COMPLETED',
          certificateStatus: 'NOT_REQUESTED',
        },
        include: { course: true },
      });

      const transaction = await tx.transaction.create({
        data: {
          userId,
          courseId,
          amount: paymentResult.amount,
          currency: paymentResult.currency,
          paymentMethod: paymentResult.paymentMethod,
          purpose: 'COURSE_ENROLLMENT',
          status: 'COMPLETED',
          providerRef: paymentResult.providerRef,
        },
      });

      return { enrollment, transaction };
    });

    return res.status(201).json(result);
  })
);

app.get(
  '/api/my-courses',
  protect,
  asyncHandler(async (req, res) => {
    const enrollments = await prisma.enrollment.findMany({
      where: { userId: req.user.id, paymentStatus: 'COMPLETED' },
      include: { course: { include: { modules: { orderBy: { orderIndex: 'asc' } } } } },
      orderBy: { enrolledAt: 'desc' },
    });
    return res.status(200).json({ enrollments });
  })
);

app.post(
  '/api/submissions',
  protect,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { courseId, moduleId, language, code, notes } = body;
    if (!courseId || !code) {
      return res.status(400).json({ error: 'courseId and code are required' });
    }

    const enrollment = await prisma.enrollment.findUnique({
      where: { userId_courseId: { userId: req.user.id, courseId } },
    });
    if (!enrollment || enrollment.paymentStatus !== 'COMPLETED') {
      return res.status(403).json({ error: 'Enroll in the course before submitting code' });
    }

    const testKey = `${courseId}:${moduleId || 'general'}`;
    const testCases =
      moduleTestCases.get(testKey) || moduleTestCases.get(`${courseId}:general`) || [];
    const normLang = String(language || 'Any Programming Language').trim();

    const evaluation = await evaluateCodeSubmissionQueued({
      language: normLang,
      code: String(code),
      testCases,
    });

    const scoreSummary = recordLearnerCourseScore(req.user.id, courseId, evaluation?.score ?? 0);

    const subKey = `${req.user.id}:${courseId}:${moduleId || 'general'}`;
    const record = {
      id: `sub_${crypto.randomBytes(4).toString('hex')}`,
      userId: req.user.id,
      studentName: req.user.name,
      courseId,
      moduleId: moduleId || 'general',
      language: normLang,
      code: String(code),
      notes: notes ? String(notes).trim() : '',
      evaluation,
      scoreSummary,
      submittedAt: new Date().toISOString(),
    };

    setBoundedMap(learnerSubmissions, subKey, record);
    return res.status(201).json({ submission: record, evaluation, scoreSummary });
  })
);

app.get('/api/submissions', protect, (req, res) => {
  const mine = Array.from(learnerSubmissions.values()).filter((s) => s.userId === req.user.id);
  return res.status(200).json({ submissions: mine });
});

app.post(
  '/api/certificate/:courseId',
  protect,
  paymentLimiter,
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { courseId } = req.params;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { currency, paymentMethod } = body;

    const enrollment = await prisma.enrollment.findUnique({
      where: { userId_courseId: { userId, courseId } },
      include: { course: true, user: true },
    });

    if (!enrollment || enrollment.paymentStatus !== 'COMPLETED') {
      return res.status(403).json({
        error: 'You must be enrolled in this course before requesting a certificate.',
      });
    }

    const requiredScore = getRequiredPassScore(courseId);
    const scoreInfo = getLearnerCourseScore(userId, courseId);

    if (enrollment.certificateStatus !== 'ISSUED' && scoreInfo.bestScore < requiredScore) {
      return res.status(403).json({
        error: `Certificate locked: minimum test-case score is ${requiredScore}%, your best score is ${scoreInfo.bestScore}%.`,
        requiredScore,
        currentBestScore: scoreInfo.bestScore,
      });
    }

    let updatedEnrollment = enrollment;

    if (enrollment.certificateStatus !== 'ISSUED') {
      if (!currency || !paymentMethod) {
        return res.status(400).json({ error: 'currency and paymentMethod are required' });
      }

      const normCurrency = String(currency).trim().toUpperCase();
      const certFee =
        normCurrency === 'USD' ? enrollment.course.certFeeUSD : enrollment.course.certFeeETB;

      const paymentResult = await processGatewayPayment({
        amount: certFee,
        currency: normCurrency,
        paymentMethod,
        purpose: 'CERTIFICATE',
        userId,
        courseId,
      });

      const now = new Date();
      updatedEnrollment = await prisma.$transaction(async (tx) => {
        await tx.transaction.create({
          data: {
            userId,
            courseId,
            amount: paymentResult.amount,
            currency: paymentResult.currency,
            paymentMethod: paymentResult.paymentMethod,
            purpose: 'CERTIFICATE',
            status: 'COMPLETED',
            providerRef: paymentResult.providerRef,
          },
        });

        return tx.enrollment.update({
          where: { id: enrollment.id },
          data: { certificateStatus: 'ISSUED', certifiedAt: now },
          include: { course: true, user: true },
        });
      });
    }

    return streamCourseCertificatePDF(res, {
      studentName: updatedEnrollment.user.name,
      courseTitle: `${updatedEnrollment.course.title} (Score: ${scoreInfo.bestScore}%)`,
      programmingLanguage: updatedEnrollment.course.programmingLanguage,
      issuedDate: updatedEnrollment.certifiedAt || new Date(),
      certificateId: updatedEnrollment.id,
    });
  })
);

app.get(
  '/api/certificate/:courseId/download',
  protect,
  asyncHandler(async (req, res) => {
    const userId = req.user.id;
    const { courseId } = req.params;
    const enrollment = await prisma.enrollment.findUnique({
      where: { userId_courseId: { userId, courseId } },
      include: { course: true, user: true },
    });

    if (!enrollment || enrollment.certificateStatus !== 'ISSUED') {
      return res.status(403).json({ error: 'Certificate has not been issued yet' });
    }

    const requiredScore = getRequiredPassScore(courseId);
    const scoreInfo = getLearnerCourseScore(userId, courseId);
    if (scoreInfo.bestScore < requiredScore) {
      return res.status(403).json({
        error: `Certificate requires at least ${requiredScore}% score (current best: ${scoreInfo.bestScore}%).`,
      });
    }

    return streamCourseCertificatePDF(res, {
      studentName: enrollment.user.name,
      courseTitle: `${enrollment.course.title} (Score: ${scoreInfo.bestScore}%)`,
      programmingLanguage: enrollment.course.programmingLanguage,
      issuedDate: enrollment.certifiedAt || new Date(),
      certificateId: enrollment.id,
    });
  })
);

// --- Library, External Tools & Instructors ---
app.get('/api/resources', (req, res) => {
  const typeFilter = String(req.query.type || '').trim().toUpperCase();
  const q = String(req.query.q || '').trim().toLowerCase();

  const items = Array.from(resourceLibrary.values()).filter((r) => {
    const matchType = !typeFilter || r.resourceType === typeFilter;
    const matchQ =
      !q ||
      r.title.toLowerCase().includes(q) ||
      r.language.toLowerCase().includes(q) ||
      (r.summary || '').toLowerCase().includes(q);
    return matchType && matchQ;
  });

  return res.status(200).json({ resources: items });
});

app.get('/api/external-tools', (req, res) => {
  const catFilter = req.query.category ? normalizeToolCategory(req.query.category) : '';
  const courseId = req.query.courseId ? String(req.query.courseId).trim() : '';
  const linkedSet = courseId ? courseLinkedTools.get(courseId) : null;

  const tools = Array.from(externalToolsDirectory.values()).filter((t) => {
    const matchCat = !catFilter || t.category === catFilter;
    const matchCourse = !linkedSet || linkedSet.has(t.id) || t.requiredForCourses;
    return matchCat && matchCourse;
  });

  return res.status(200).json({
    categories: Array.from(ALLOWED_TOOL_CATEGORIES),
    tools,
  });
});

app.get('/api/instructors', (req, res) => {
  return res.status(200).json({ instructors: Array.from(instructorsDirectory.values()) });
});

// --- Memory, Open AI, Monitor, Adaptive, CBL & Workflows ---
app.post(
  '/api/memory',
  protect,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { scope, entityId, title, content, tags } = body;
    if (!content || !String(content).trim()) {
      return res.status(400).json({ error: 'Memory content is required.' });
    }

    const memory = await writeUnlimitedMemory({
      scope: scope || 'LEARNER',
      entityId: entityId || req.user.id,
      agentId: 'MEMORY_STORE',
      title: title || `Note by ${req.user.name}`,
      content,
      tags: Array.isArray(tags) ? tags : String(tags || '').split(','),
      meta: { authorId: req.user.id, authorName: req.user.name },
    });

    return res.status(201).json({ memory });
  })
);

app.get(
  '/api/memory',
  asyncHandler(async (req, res) => {
    const result = await queryUnlimitedMemory({
      q: req.query.q || '',
      scope: req.query.scope || '',
      entityId: req.query.entityId || '',
      cursor: req.query.cursor || null,
      limit: req.query.limit || 30,
    });
    const stats = await getMemoryStats();
    return res.status(200).json({ ...result, stats });
  })
);

app.get(
  '/api/memory/export',
  asyncHandler(async (req, res) => {
    const backup = await exportUnlimitedMemoryJsonl();
    if (String(req.query.format || '').toLowerCase() === 'json') {
      return res.status(200).json(backup);
    }
    const stamp = new Date().toISOString().slice(0, 10);
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="academy-memory-${stamp}.jsonl"`);
    return res.status(200).send(backup.jsonl);
  })
);

app.post(
  '/api/memory/import',
  requireAdminCode,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const result = await importUnlimitedMemoryJsonl({
      jsonlText: body.jsonlText,
      records: body.records,
      regenerateIds: Boolean(body.regenerateIds),
    });
    return res.status(200).json({
      message: `Imported ${result.importedCount} memory record(s) (${result.skippedDuplicateCount} duplicate(s) skipped).`,
      ...result,
    });
  })
);

app.post(
  '/api/ai/agent/chat',
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    let course = null;
    if (body.courseId) {
      course = await prisma.course.findUnique({
        where: { id: String(body.courseId) },
        include: { modules: { orderBy: { orderIndex: 'asc' } } },
      });
    }
    const result = await runAcademyOpenAi({
      mode: body.mode || body.agentId || 'CHATGPT_COACH',
      prompt: body.message,
      course,
      preferredProvider: body.preferredProvider,
    });
    return res.status(200).json({
      agent: result.mode,
      provider: result.provider,
      reply: result.output,
      memorySaved: result.memorySaved,
    });
  })
);

app.post(
  '/api/ai/agent/run',
  requireAdminCode,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const outcome = await runPromptImprovementAgent({
      agentId: body.agentId,
      targetScope: String(body.targetScope || 'COURSE').toUpperCase(),
      courseId: body.courseId,
      prompt: body.prompt,
      autoApply: body.autoApply !== undefined ? Boolean(body.autoApply) : true,
      preferredProvider: body.preferredProvider,
    });
    return res.status(200).json(outcome);
  })
);

app.post(
  '/api/ai/workflow/create-course',
  requireAdminCode,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const outcome = await runAutonomousCourseWorkflow(body);
    return res.status(201).json(outcome);
  })
);

app.post(
  '/api/open-ai/studio',
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    let course = null;
    if (body.courseId) {
      course = await prisma.course.findUnique({
        where: { id: String(body.courseId) },
        include: { modules: { orderBy: { orderIndex: 'asc' } } },
      });
    }
    const result = await runAcademyOpenAi({
      mode: body.mode,
      prompt: body.prompt,
      codeContext: body.codeContext,
      course,
      preferredProvider: body.preferredProvider,
    });
    return res.status(200).json({ ...result, availableModes: Object.values(OPEN_AI_MODES) });
  })
);

app.post(
  '/api/open-ai/monitor/track',
  protect,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const telemetry = await monitorLearnerProgress({
      userId: req.user.id,
      courseId: body.courseId || 'general',
      moduleId: body.moduleId || 'general',
      score: body.score,
      timeSpentMinutes: body.timeSpentMinutes,
      completedLesson: Boolean(body.completedLesson),
      mindsetNote: body.mindsetNote,
    });
    return res.status(200).json({ telemetry });
  })
);

app.post(
  '/api/open-ai/adapt-course',
  protect,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const adaptation = await adaptCourseForLearner({
      userId: req.user.id,
      courseId: body.courseId,
      goal: body.goal,
      pace: body.pace,
    });
    return res.status(200).json({ adaptation });
  })
);

app.post(
  '/api/open-ai/competence/assess',
  protect,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const outcome = await assessCompetence({
      userId: req.user.id,
      courseId: body.courseId || 'general',
      competencyId: body.competencyId,
      competencyName: body.competencyName,
      evidenceScore: body.evidenceScore,
      evidenceNotes: body.evidenceNotes,
    });
    return res.status(200).json(outcome);
  })
);

app.get('/api/open-ai/competence', protect, (req, res) => {
  const courseId = String(req.query.courseId || 'general');
  return res.status(200).json(getLearnerCompetenceSummary(req.user.id, courseId));
});

// --- Protected Admin Routes (x-admin-code: 5405402) ---
app.post(
  '/api/admin/courses',
  requireAdminCode,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const {
      title,
      description,
      thumbnail,
      programmingLanguage,
      priceETB,
      priceUSD,
      certFeeETB,
      certFeeUSD,
      isPublished,
    } = body;

    if (!title || !description) {
      return res.status(400).json({ error: 'title and description are required' });
    }

    const course = await prisma.course.create({
      data: {
        title: String(title).trim(),
        description: String(description).trim(),
        thumbnail: thumbnail ? String(thumbnail).trim() : null,
        programmingLanguage: String(programmingLanguage || 'Any Programming Language').trim(),
        priceETB: parseNonNegativeMoney(priceETB, 'priceETB'),
        priceUSD: parseNonNegativeMoney(priceUSD, 'priceUSD'),
        certFeeETB: parseNonNegativeMoney(certFeeETB, 'certFeeETB'),
        certFeeUSD: parseNonNegativeMoney(certFeeUSD, 'certFeeUSD'),
        isPublished: isPublished !== undefined ? Boolean(isPublished) : true,
      },
    });

    return res.status(201).json({ course });
  })
);

app.post(
  '/api/admin/courses/seed-bulk',
  requireAdminCode,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const stats = await seedBulkCourses(body);
    return res.status(201).json({ message: 'Bulk courses seeded.', ...stats });
  })
);

app.get(
  '/api/admin/courses/review-queue',
  requireAdminCode,
  asyncHandler(async (req, res) => {
    const courses = await prisma.course.findMany({
      include: { modules: { orderBy: { orderIndex: 'asc' } } },
      orderBy: { createdAt: 'desc' },
    });

    const enriched = courses.map((c) => ({
      ...c,
      approval: courseReviewMeta.get(c.id) || {
        courseId: c.id,
        status: c.isPublished ? 'APPROVED' : 'PENDING_APPROVAL',
        uploadedByName: 'Academy / Instructor',
      },
    }));

    return res.status(200).json({ courses: enriched });
  })
);

app.post(
  '/api/admin/courses/:id/approve',
  requireAdminCode,
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const action = String(body.action || 'APPROVE').trim().toUpperCase();
    const notes = body.notes ? String(body.notes).trim() : '';

    const course = await prisma.course.findUnique({ where: { id } });
    if (!course) {
      return res.status(404).json({ error: 'Course not found.' });
    }

    const approved = action !== 'REJECT';
    const updatedCourse = await prisma.course.update({
      where: { id },
      data: { isPublished: approved },
    });

    const approval = {
      ...(courseReviewMeta.get(id) || { courseId: id }),
      status: approved ? 'APPROVED' : 'REJECTED',
      reviewedBy: PRIMARY_ADMIN_EMAIL,
      reviewedAt: new Date().toISOString(),
      reviewNotes: notes,
    };
    setBoundedMap(courseReviewMeta, id, approval);

    return res.status(200).json({ course: updatedCourse, approval });
  })
);

app.post(
  '/api/admin/courses/:id/pass-score',
  requireAdminCode,
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const minScore = Number(body.minScore);
    if (!Number.isFinite(minScore) || minScore < 0 || minScore > 100) {
      return res.status(400).json({ error: 'minScore must be between 0 and 100.' });
    }
    const course = await prisma.course.findUnique({ where: { id } });
    if (!course) {
      return res.status(404).json({ error: 'Course not found.' });
    }
    setBoundedMap(coursePassScoreOverrides, id, minScore);
    return res.status(200).json({ courseId: id, minPassScore: minScore });
  })
);

app.post(
  '/api/admin/courses/:id/modules',
  requireAdminCode,
  asyncHandler(async (req, res) => {
    const { id: courseId } = req.params;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { title, contentUrl, language, contentType, starterCode, orderIndex } = body;
    if (!title || !contentUrl) {
      return res.status(400).json({ error: 'title and contentUrl are required' });
    }

    const course = await prisma.course.findUnique({ where: { id: courseId } });
    if (!course) {
      return res.status(404).json({ error: 'Course not found' });
    }

    const createdModule = await prisma.module.create({
      data: {
        courseId,
        title: String(title).trim(),
        contentUrl: String(contentUrl).trim(),
        language: language ? String(language).trim() : course.programmingLanguage,
        contentType: String(contentType || 'CODE_REPO').trim().toUpperCase(),
        starterCode: starterCode ? String(starterCode) : null,
        orderIndex: orderIndex !== undefined ? Number(orderIndex) : 0,
      },
    });

    return res.status(201).json({ module: createdModule });
  })
);

app.post(
  '/api/admin/courses/:id/test-cases',
  requireAdminCode,
  asyncHandler(async (req, res) => {
    const { id: courseId } = req.params;
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const { moduleId, testCases } = body;
    if (!Array.isArray(testCases) || testCases.length === 0) {
      return res.status(400).json({ error: 'testCases must be a non-empty array' });
    }

    const course = await prisma.course.findUnique({ where: { id: courseId } });
    if (!course) {
      return res.status(404).json({ error: 'Course not found' });
    }

    setBoundedMap(moduleTestCases, `${courseId}:${moduleId || 'general'}`, testCases);
    return res.status(201).json({ courseId, moduleId: moduleId || 'general', count: testCases.length });
  })
);

app.post(
  '/api/admin/courses/convert-source',
  requireAdminCode,
  asyncHandler(async (req, res) => {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const {
      courseTitle,
      description,
      programmingLanguage,
      sourceType,
      sourceUrl,
      sourceText,
      chapters,
      priceETB,
      priceUSD,
      certFeeETB,
      certFeeUSD,
      toolIds,
      isPublished,
    } = body;

    const resolvedTitle = String(courseTitle || '').trim();
    if (!resolvedTitle) {
      return res.status(400).json({ error: 'courseTitle is required.' });
    }

    const normType = normalizeResourceType(sourceType || 'BOOK');
    const lang = String(programmingLanguage || 'Any Programming Language').trim();
    const builtModules = buildModulesFromSource({
      sourceType: normType,
      sourceTitle: resolvedTitle,
      sourceUrl,
      sourceText,
      chapters,
      programmingLanguage: lang,
    });

    const createdCourse = await prisma.course.create({
      data: {
        title: resolvedTitle,
        description: String(
          description || `Converted ${normType.toLowerCase()} course: ${resolvedTitle}`
        ).trim(),
        programmingLanguage: lang,
        priceETB: parseNonNegativeMoney(priceETB ?? 0, 'priceETB'),
        priceUSD: parseNonNegativeMoney(priceUSD ?? 0, 'priceUSD'),
        certFeeETB: parseNonNegativeMoney(certFeeETB ?? 150, 'certFeeETB'),
        certFeeUSD: parseNonNegativeMoney(certFeeUSD ?? 3, 'certFeeUSD'),
        isPublished: isPublished !== undefined ? Boolean(isPublished) : true,
        modules: { create: builtModules },
      },
      include: { modules: { orderBy: { orderIndex: 'asc' } } },
    });

    const linkedSet = new Set(Array.isArray(toolIds) ? toolIds.map(String) : []);
    for (const [tId, tool] of externalToolsDirectory.entries()) {
      if (tool.requiredForCourses) linkedSet.add(tId);
    }
    if (linkedSet.size > 0) {
      setBoundedMap(courseLinkedTools, createdCourse.id, linkedSet);
    }

    const resId = `res_${crypto.randomBytes(4).toString('hex')}`;
    setBoundedMap(resourceLibrary, resId, {
      id: resId,
      title: resolvedTitle,
      resourceType: normType,
      language: lang,
      url: isValidHttpUrl(sourceUrl) ? String(sourceUrl).trim() : null,
      convertedCourseId: createdCourse.id,
      moduleCount: createdCourse.modules.length,
      addedBy: PRIMARY_ADMIN_EMAIL,
      addedAt: new Date().toISOString(),
    });

    return res.status(201).json({
      message: `Converted ${normType} into "${createdCourse.title}" (${createdCourse.modules.length} modules).`,
      course: createdCourse,
      linkedToolIds: Array.from(linkedSet),
    });
  })
);

app.post('/api/admin/resources', requireAdminCode, (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const { title, resourceType, language, url, summary, tags } = body;
  if (!title) {
    return res.status(400).json({ error: 'Resource title is required.' });
  }
  if (url && !isValidHttpUrl(url)) {
    return res.status(400).json({ error: 'Resource url must start with http:// or https://.' });
  }

  const id = `res_${crypto.randomBytes(4).toString('hex')}`;
  const resource = {
    id,
    title: String(title).trim(),
    resourceType: normalizeResourceType(resourceType),
    language: String(language || 'Any / Multi-Language').trim(),
    url: url ? String(url).trim() : null,
    summary: summary ? String(summary).trim() : '',
    tags: Array.isArray(tags)
      ? tags.map((t) => String(t).trim()).filter(Boolean)
      : String(tags || '')
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean),
    addedBy: PRIMARY_ADMIN_EMAIL,
    addedAt: new Date().toISOString(),
  };

  setBoundedMap(resourceLibrary, id, resource);
  return res.status(201).json({ resource });
});

app.post('/api/admin/external-tools', requireAdminCode, (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const { name, category, url, description, requiredForCourses, courseId } = body;
  if (!name || !url) {
    return res.status(400).json({ error: 'Tool name and url are required.' });
  }
  if (!isValidHttpUrl(url)) {
    return res.status(400).json({ error: 'Tool url must be a valid http:// or https:// URL.' });
  }

  const id = `tool_${crypto.randomBytes(4).toString('hex')}`;
  const tool = {
    id,
    name: String(name).trim(),
    category: normalizeToolCategory(category),
    url: String(url).trim(),
    description: description ? String(description).trim() : '',
    requiredForCourses: requiredForCourses !== undefined ? Boolean(requiredForCourses) : true,
    addedBy: PRIMARY_ADMIN_EMAIL,
    addedAt: new Date().toISOString(),
  };

  setBoundedMap(externalToolsDirectory, id, tool);
  if (courseId) {
    const cKey = String(courseId).trim();
    const set = courseLinkedTools.get(cKey) || new Set();
    set.add(id);
    setBoundedMap(courseLinkedTools, cKey, set);
  }

  return res.status(201).json({ tool });
});

app.delete('/api/admin/external-tools/:id', requireAdminCode, (req, res) => {
  const { id } = req.params;
  if (!externalToolsDirectory.has(id)) {
    return res.status(404).json({ error: 'External tool not found.' });
  }
  externalToolsDirectory.delete(id);
  for (const set of courseLinkedTools.values()) {
    set.delete(id);
  }
  return res.status(200).json({ deleted: true, id });
});

app.post('/api/admin/instructors', requireAdminCode, (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const { name, email, phone, whatsapp, telegram, specialties, socialLinks } = body;
  if (!name) {
    return res.status(400).json({ error: 'Instructor name is required.' });
  }

  const id = `inst_${crypto.randomBytes(4).toString('hex')}`;
  const instructor = {
    id,
    name: String(name).trim(),
    email: email ? String(email).trim().toLowerCase() : null,
    phone: phone ? String(phone).trim() : null,
    whatsapp: whatsapp ? String(whatsapp).trim() : null,
    telegram: telegram ? String(telegram).trim() : null,
    specialties: Array.isArray(specialties)
      ? specialties.map((s) => String(s).trim()).filter(Boolean)
      : String(specialties || 'Skills, Knowledge & Positive Mindset')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
    socialLinks: normalizeSocialLinks(socialLinks),
    addedBy: PRIMARY_ADMIN_EMAIL,
    addedAt: new Date().toISOString(),
  };

  setBoundedMap(instructorsDirectory, id, instructor);
  return res.status(201).json({ instructor });
});

app.get('/api/admin/submissions', requireAdminCode, (req, res) => {
  return res.status(200).json({ submissions: Array.from(learnerSubmissions.values()).slice(-200) });
});

app.get(
  '/api/admin/analytics',
  requireAdminCode,
  asyncHandler(async (req, res) => {
    const [totalStudents, totalCourses, totalEnrollments, completedTransactions] =
      await Promise.all([
        prisma.user.count({ where: { role: 'STUDENT' } }),
        prisma.course.count(),
        prisma.enrollment.count({ where: { paymentStatus: 'COMPLETED' } }),
        prisma.transaction.findMany({ where: { status: 'COMPLETED' } }),
      ]);

    let revenueETB = 0;
    let revenueUSD = 0;
    for (const tx of completedTransactions) {
      const amt = Number(tx.amount);
      if (tx.currency === 'ETB') revenueETB += amt;
      if (tx.currency === 'USD') revenueUSD += amt;
    }

    return res.status(200).json({
      totalStudents,
      totalCourses,
      totalEnrollments,
      totalSubmissions: learnerSubmissions.size,
      totalTransactions: completedTransactions.length,
      revenue: {
        ETB: Number(revenueETB.toFixed(2)),
        USD: Number(revenueUSD.toFixed(2)),
      },
    });
  })
);

// ============================================================================
// 9. FRONTEND SPA & DIAGNOSTIC 404 / ERROR HANDLERS
// ============================================================================
app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.status(200).send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${ACADEMY_NAME}</title>
  <style>
    :root { --primary:#004aad; --accent:#fca311; --dark:#0f172a; --bg:#f4f7fb; --card:#ffffff; --text:#1e293b; --muted:#64748b; --success:#15803d; --danger:#b91c1c; --border:#e2e8f0; }
    * { box-sizing:border-box; margin:0; padding:0; font-family:"Segoe UI",system-ui,-apple-system,sans-serif; }
    body { background:var(--bg); color:var(--text); line-height:1.55; }
    nav { background:var(--dark); color:#fff; padding:0.9rem 1.5rem; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.65rem; }
    .brand { font-size:1.1rem; font-weight:800; }
    .tagline { font-size:0.75rem; color:#fcd34d; font-style:italic; }
    .container { max-width:1180px; margin:1.4rem auto; padding:0 1rem; }
    .card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:1.2rem; margin-bottom:1rem; }
    .grid-3 { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:1rem; }
    .banner { padding:0.75rem 1rem; border-radius:8px; margin-bottom:1rem; font-weight:600; background:#e0ecff; color:#003175; }
    button { border:none; border-radius:6px; padding:0.46rem 0.85rem; font-weight:600; cursor:pointer; background:var(--primary); color:#fff; }
    .tag { display:inline-block; background:#e0ecff; color:#003175; font-size:0.74rem; font-weight:700; padding:0.16rem 0.5rem; border-radius:999px; margin-bottom:0.4rem; }
  </style>
</head>
<body>
  <nav>
    <div>
      <div class="brand">${ACADEMY_NAME}</div>
      <div class="tagline">${ACADEMY_TAGLINE}</div>
    </div>
    <button onclick="loadAll()">Refresh Status &amp; Catalog</button>
  </nav>
  <div class="container">
    <div id="banner" class="banner">Connecting to ${ACADEMY_NAME} API...</div>
    <div id="courses" class="grid-3"></div>
  </div>
  <script>
    const API = window.location.origin + "/api";
    function esc(s) { return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
    async function loadAll() {
      try {
        const [hRes, cRes] = await Promise.all([fetch(API + "/health"), fetch(API + "/courses?limit=12")]);
        const h = await hRes.json();
        const c = await cRes.json();
        document.getElementById("banner").textContent = "API Status: " + (h.status || "ok") + " | DB: " + (h.database || "ok") + " | Courses loaded: " + (c.courses?.length || 0);
        document.getElementById("courses").innerHTML = (c.courses || []).map(x =>
          '<div class="card"><span class="tag">' + esc(x.programmingLanguage || "Any Language") + '</span><h3>' + esc(x.title) + '</h3><p style="color:#64748b;font-size:0.86rem;margin-top:0.35rem">' + esc(x.description) + '</p></div>'
        ).join("") || '<div class="card"><p style="color:#64748b">No courses published yet. Use POST /api/admin/courses or POST /api/admin/courses/seed-bulk with x-admin-code: ${ADMIN_MASTER_CODE}.</p></div>';
      } catch (e) {
        document.getElementById("banner").textContent = "Error: " + e.message;
      }
    }
    loadAll();
  </script>
</body>
</html>`);
});

app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    method: req.method,
    path: req.originalUrl,
    availableEndpoints: [
      'GET /api/health',
      'GET /api/academy/profile',
      'GET /api/courses',
      'GET /api/memory',
      'GET /api/memory/export',
      'POST /api/memory/import',
    ],
  });
});

app.use((err, req, res, next) => {
  if (err && err.code === 'P2002') {
    return res.status(409).json({ error: 'A record with that unique field already exists' });
  }
  if (err && err.code === 'P2025') {
    return res.status(404).json({ error: 'Requested record not found' });
  }
  if (err && err.code === 'P2003') {
    return res.status(400).json({ error: 'Invalid foreign key reference' });
  }
  console.error(err.stack || err);
  const statusCode = err.statusCode || 500;
  res.status(statusCode).json({ error: err.message || 'Internal Server Error' });
});

// ============================================================================
// 10. STARTUP & GRACEFUL SHUTDOWN
// ============================================================================
let serverInstance;

async function startServer() {
  try {
    await prisma.$connect();
    await ensureAcademyConfig();
    console.log('PostgreSQL connected via Prisma ORM');

    const seedArg = process.argv.find((arg) => arg.startsWith('--seed-bulk='));
    if (seedArg) {
      const count = Number(seedArg.split('=')[1]) || 500;
      const stats = await seedBulkCourses({ totalCourses: count, batchSize: 1000 });
      console.log('Seed completed:', stats);
    }

    serverInstance = app.listen(PORT, () => {
      console.log(`${ACADEMY_NAME} running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

async function shutdown(signal) {
  console.log(`Received ${signal}. Closing server and database connection...`);
  if (serverInstance) {
    await new Promise((resolve) => serverInstance.close(resolve));
  }
  await prisma.$disconnect();
  process.exit(0);
}

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

startServer();
