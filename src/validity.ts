// --- Context validity windows ---
// Agents often write context that's only valid for a bounded time window.
// This module parses `<!-- validity: Xh -->` (or `1d`, `3d`) annotations
// from CONTEXT.md, checks freshness against `<!-- openfuse:added: ISO -->`,
// and provides soft-expiry confidence scoring via exponential decay.
//
// Design decisions:
// - Advisory only: agents that don't understand validity annotations read
//   CONTEXT.md normally. No schema enforcement.
// - Decay starts at write time, reaches 0.5 at TTL, asymptotes toward 0.
//   Agents can down-weight uncertain context rather than hard-drop it.
// - "Stale" means confidence < 0.1 (roughly 3× TTL from write time).

export interface ValidityAnnotation {
  /** Validity window parsed from <!-- validity: ... --> */
  ttlMs: number;
  /** Written timestamp from <!-- openfuse:added: ISO --> (if present) */
  addedAt?: Date;
  /** True if confidence < 0.1 */
  expired: boolean;
  /** Soft confidence [0, 1]. 1.0 at write time, 0.5 at TTL, asymptotes to 0 */
  confidence: number;
  /** The section text following this annotation (until the next annotation or EOF) */
  sectionText: string;
}

export interface ValidityReport {
  total: number;
  stale: number;
  fresh: number;
  entries: Array<{
    preview: string;
    addedAt: string | null;
    ttlLabel: string;
    confidence: number;
    expired: boolean;
  }>;
}

// --- Parsing ---

const VALIDITY_RE = /<!--\s*validity:\s*(\d+)\s*(h|d)\s*(?:,\s*[^>]*)?\s*-->/i;
const ADDED_RE = /<!--\s*openfuse:added:\s*([^\s>]+)\s*-->/i;

/** Parse a TTL label like "6h" or "3d" into milliseconds */
export function parseTtlMs(value: string, unit: string): number {
  const n = parseInt(value, 10);
  if (unit.toLowerCase() === "d") return n * 24 * 60 * 60 * 1000;
  return n * 60 * 60 * 1000; // hours default
}

/** Soft-expiry confidence. Exponential decay: 1.0 at write, 0.5 at TTL, →0 over time. */
export function computeConfidence(
  addedAt: Date | undefined,
  ttlMs: number,
  now: Date = new Date()
): number {
  if (!addedAt) {
    // No timestamp — treat as written "now" with full confidence
    return 1.0;
  }
  const ageMs = now.getTime() - addedAt.getTime();
  if (ageMs <= 0) return 1.0;
  // Exponential decay: confidence = 0.5 ^ (age / ttl)
  return Math.pow(0.5, ageMs / ttlMs);
}

/**
 * Parse CONTEXT.md content for validity-annotated sections.
 * Each `<!-- validity: Xh -->` comment starts a new annotated section.
 * Sections without validity annotations are skipped.
 */
export function parseValiditySections(
  content: string,
  now: Date = new Date()
): ValidityAnnotation[] {
  const results: ValidityAnnotation[] = [];
  const lines = content.split("\n");

  let inSection = false;
  let currentTtlMs = 0;
  let currentAddedAt: Date | undefined;
  let sectionLines: string[] = [];

  const flushSection = () => {
    if (!inSection) return;
    const confidence = computeConfidence(currentAddedAt, currentTtlMs, now);
    results.push({
      ttlMs: currentTtlMs,
      addedAt: currentAddedAt,
      expired: confidence < 0.1,
      confidence,
      sectionText: sectionLines.join("\n").trim(),
    });
    inSection = false;
    sectionLines = [];
    currentAddedAt = undefined;
    currentTtlMs = 0;
  };

  for (const line of lines) {
    const validityMatch = line.match(VALIDITY_RE);
    if (validityMatch) {
      flushSection();
      currentTtlMs = parseTtlMs(validityMatch[1], validityMatch[2]);
      inSection = true;
      continue;
    }

    const addedMatch = line.match(ADDED_RE);
    if (addedMatch && inSection && !currentAddedAt) {
      const parsed = new Date(addedMatch[1]);
      if (!isNaN(parsed.getTime())) {
        currentAddedAt = parsed;
      }
      continue;
    }

    if (inSection) {
      sectionLines.push(line);
    }
  }

  flushSection();
  return results;
}

/** Build a human-readable report of validity window status */
export function buildValidityReport(
  sections: ValidityAnnotation[]
): ValidityReport {
  const entries = sections.map((s) => {
    const preview =
      s.sectionText.split("\n").find((l) => l.trim()) ?? "(empty)";
    const ttlMs = s.ttlMs;
    const hours = ttlMs / (60 * 60 * 1000);
    const ttlLabel =
      hours >= 24 ? `${Math.round(hours / 24)}d` : `${Math.round(hours)}h`;
    return {
      preview: preview.slice(0, 80),
      addedAt: s.addedAt ? s.addedAt.toISOString() : null,
      ttlLabel,
      confidence: Math.round(s.confidence * 100) / 100,
      expired: s.expired,
    };
  });

  return {
    total: sections.length,
    stale: sections.filter((s) => s.expired).length,
    fresh: sections.filter((s) => !s.expired).length,
    entries,
  };
}

// --- Default TTL tiers (from multi-agent swarm research) ---
// Based on 20-agent, 20-run PDR evaluation dataset:
//   task-state context (what I'm working on right now): ~6h half-life
//   sprint-context (sprint goals, current approach): ~24h half-life
//   project-architecture (design decisions, constraints): ~72h half-life
export const DEFAULT_TTL_TIERS = {
  task: 6 * 60 * 60 * 1000,        // 6h
  sprint: 24 * 60 * 60 * 1000,     // 24h
  architecture: 72 * 60 * 60 * 1000, // 72h
} as const;
