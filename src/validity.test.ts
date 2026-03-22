// Tests for context validity window module
// Run: node --import tsx/esm src/validity.test.ts
// (or after build: node dist/validity.test.js)
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseTtlMs,
  computeConfidence,
  parseValiditySections,
  buildValidityReport,
  DEFAULT_TTL_TIERS,
} from "./validity.js";

// --- parseTtlMs ---

describe("parseTtlMs", () => {
  it("parses hours", () => {
    assert.equal(parseTtlMs("6", "h"), 6 * 60 * 60 * 1000);
  });
  it("parses days", () => {
    assert.equal(parseTtlMs("3", "d"), 3 * 24 * 60 * 60 * 1000);
  });
  it("parses 1d", () => {
    assert.equal(parseTtlMs("1", "d"), 24 * 60 * 60 * 1000);
  });
  it("parses 24h", () => {
    assert.equal(parseTtlMs("24", "H"), 24 * 60 * 60 * 1000);
  });
});

// --- computeConfidence ---

describe("computeConfidence", () => {
  const ttl6h = 6 * 60 * 60 * 1000;

  it("returns 1.0 when no addedAt (no timestamp)", () => {
    assert.equal(computeConfidence(undefined, ttl6h), 1.0);
  });

  it("returns 1.0 at write time", () => {
    const now = new Date("2026-03-21T12:00:00Z");
    const addedAt = new Date("2026-03-21T12:00:00Z");
    assert.equal(computeConfidence(addedAt, ttl6h, now), 1.0);
  });

  it("returns 0.5 at TTL boundary", () => {
    const addedAt = new Date("2026-03-21T00:00:00Z");
    const now = new Date("2026-03-21T06:00:00Z"); // exactly 6h later
    const conf = computeConfidence(addedAt, ttl6h, now);
    assert.ok(Math.abs(conf - 0.5) < 0.0001, `expected ~0.5, got ${conf}`);
  });

  it("returns ~0.25 at 2× TTL", () => {
    const addedAt = new Date("2026-03-21T00:00:00Z");
    const now = new Date("2026-03-21T12:00:00Z"); // 12h = 2× TTL
    const conf = computeConfidence(addedAt, ttl6h, now);
    assert.ok(Math.abs(conf - 0.25) < 0.0001, `expected ~0.25, got ${conf}`);
  });

  it("returns < 0.1 at 3.32× TTL (expired threshold)", () => {
    const addedAt = new Date("2026-03-21T00:00:00Z");
    const now = new Date("2026-03-21T20:00:00Z"); // 20h ≈ 3.33× TTL
    const conf = computeConfidence(addedAt, ttl6h, now);
    assert.ok(conf < 0.1, `expected < 0.1, got ${conf}`);
  });

  it("handles future addedAt gracefully (returns 1.0)", () => {
    const addedAt = new Date("2026-03-22T00:00:00Z");
    const now = new Date("2026-03-21T12:00:00Z");
    assert.equal(computeConfidence(addedAt, ttl6h, now), 1.0);
  });
});

// --- parseValiditySections ---

describe("parseValiditySections", () => {
  it("returns empty array when no validity annotations", () => {
    const content = "# Context\n\nWorking on: auth refactor\n";
    const sections = parseValiditySections(content);
    assert.equal(sections.length, 0);
  });

  it("parses a single validity section with addedAt", () => {
    const addedAt = "2026-03-21T10:00:00Z";
    const now = new Date("2026-03-21T13:00:00Z"); // 3h after write
    const content = [
      "<!-- validity: 6h -->",
      `<!-- openfuse:added: ${addedAt} -->`,
      "Working on: auth refactor",
      "Blocked on: IAM role",
    ].join("\n");
    const sections = parseValiditySections(content, now);
    assert.equal(sections.length, 1);
    assert.equal(sections[0].ttlMs, 6 * 60 * 60 * 1000);
    // toISOString() returns .000Z suffix; just check the date round-trips
    assert.ok(sections[0].addedAt instanceof Date);
    assert.equal(sections[0].addedAt!.getTime(), new Date(addedAt).getTime());
    assert.ok(sections[0].confidence > 0.5, "should be > 0.5 at 3h of 6h TTL");
    assert.equal(sections[0].expired, false);
    assert.ok(sections[0].sectionText.includes("auth refactor"));
  });

  it("parses a section without addedAt (confidence = 1.0)", () => {
    const content = [
      "<!-- validity: 1d -->",
      "Architecture: JWT with 15-minute expiry",
    ].join("\n");
    const sections = parseValiditySections(content);
    assert.equal(sections.length, 1);
    assert.equal(sections[0].addedAt, undefined);
    assert.equal(sections[0].confidence, 1.0);
    assert.equal(sections[0].expired, false);
  });

  it("marks expired sections correctly", () => {
    const addedAt = "2026-03-20T00:00:00Z"; // 48h ago
    const now = new Date("2026-03-22T00:00:00Z");
    const content = [
      "<!-- validity: 6h -->",
      `<!-- openfuse:added: ${addedAt} -->`,
      "Blocked on: IAM role",
    ].join("\n");
    const sections = parseValiditySections(content, now);
    assert.equal(sections.length, 1);
    assert.equal(sections[0].expired, true);
    assert.ok(sections[0].confidence < 0.1);
  });

  it("parses multiple validity sections independently", () => {
    const now = new Date("2026-03-22T00:00:00Z");
    const freshAdded = "2026-03-21T23:00:00Z"; // 1h ago — fresh vs 6h TTL
    const staleAdded = "2026-03-18T00:00:00Z";  // 96h ago — expired vs 24h TTL (0.5^4 = 0.0625 < 0.1)
    const content = [
      "# Context",
      "",
      "<!-- validity: 6h -->",
      `<!-- openfuse:added: ${freshAdded} -->`,
      "Working on: auth refactor",
      "",
      "<!-- validity: 1d -->",
      `<!-- openfuse:added: ${staleAdded} -->`,
      "Sprint goal: ship auth by Friday",
    ].join("\n");
    const sections = parseValiditySections(content, now);
    assert.equal(sections.length, 2);
    assert.equal(sections[0].expired, false);
    assert.equal(sections[1].expired, true);
  });

  it("parses validity with component annotation", () => {
    const content = [
      "<!-- validity: 6h, component: auth-gateway -->",
      "Working on: JWT refactor",
    ].join("\n");
    const sections = parseValiditySections(content);
    assert.equal(sections.length, 1);
    assert.equal(sections[0].ttlMs, 6 * 60 * 60 * 1000);
  });

  it("parses day-based TTL", () => {
    const content = [
      "<!-- validity: 3d -->",
      "Architecture: microservices with shared auth layer",
    ].join("\n");
    const sections = parseValiditySections(content);
    assert.equal(sections.length, 1);
    assert.equal(sections[0].ttlMs, 3 * 24 * 60 * 60 * 1000);
  });
});

// --- buildValidityReport ---

describe("buildValidityReport", () => {
  it("returns correct counts for mixed fresh/stale", () => {
    const now = new Date("2026-03-22T00:00:00Z");
    const freshAdded = "2026-03-21T23:00:00Z";
    const staleAdded = "2026-03-20T00:00:00Z";
    const content = [
      "<!-- validity: 6h -->",
      `<!-- openfuse:added: ${freshAdded} -->`,
      "Working on: auth refactor",
      "",
      "<!-- validity: 6h -->",
      `<!-- openfuse:added: ${staleAdded} -->`,
      "Blocked on: IAM role (OLD)",
    ].join("\n");
    const sections = parseValiditySections(content, now);
    const report = buildValidityReport(sections);
    assert.equal(report.total, 2);
    assert.equal(report.fresh, 1);
    assert.equal(report.stale, 1);
  });

  it("formats ttlLabel correctly for hours and days", () => {
    const content = [
      "<!-- validity: 6h -->",
      "Task context",
      "",
      "<!-- validity: 1d -->",
      "Sprint context",
      "",
      "<!-- validity: 3d -->",
      "Architecture context",
    ].join("\n");
    const sections = parseValiditySections(content);
    const report = buildValidityReport(sections);
    assert.equal(report.entries[0].ttlLabel, "6h");
    assert.equal(report.entries[1].ttlLabel, "1d");
    assert.equal(report.entries[2].ttlLabel, "3d");
  });

  it("truncates long section previews to 80 chars", () => {
    const longLine = "A".repeat(100);
    const content = `<!-- validity: 6h -->\n${longLine}`;
    const sections = parseValiditySections(content);
    const report = buildValidityReport(sections);
    assert.ok(report.entries[0].preview.length <= 80);
  });
});

// --- DEFAULT_TTL_TIERS ---

describe("DEFAULT_TTL_TIERS", () => {
  it("has expected values", () => {
    assert.equal(DEFAULT_TTL_TIERS.task, 6 * 60 * 60 * 1000);
    assert.equal(DEFAULT_TTL_TIERS.sprint, 24 * 60 * 60 * 1000);
    assert.equal(DEFAULT_TTL_TIERS.architecture, 72 * 60 * 60 * 1000);
  });
});
