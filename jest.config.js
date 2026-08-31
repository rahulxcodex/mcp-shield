const { createDefaultPreset } = require("ts-jest");

const tsJestTransformCfg = createDefaultPreset().transform;

/** @type {import("jest").Config} **/
module.exports = {
  testEnvironment: "node",
  maxWorkers: 1,
  testTimeout: 30000,
  testMatch: ["**/tests/**/*.test.ts"],
  modulePathIgnorePatterns: ["<rootDir>/dist"],
  setupFiles: ["<rootDir>/tests/setup-tree-sitter.ts"],
  collectCoverageFrom: [
    "src/security/**/*.ts",
    "src/core/stream-framing.ts",
    "src/sandbox/**/*.ts",
    "!src/security/capabilities.ts",
    "!src/security/network-proxy.ts",
    "!src/**/*.d.ts"
  ],
  coverageReporters: ["text", "lcov", "json-summary"],
  coverageThreshold: {
    global: {
      lines: 75,
      functions: 75,
      statements: 75
    }
  },
  transform: {
    ...tsJestTransformCfg,
  },
};