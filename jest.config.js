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
    "src/core/protocol-validator.ts",
    "src/core/pipeline/**/*.ts",
    "src/core/stream-framing.ts",
    "src/sandbox/**/*.ts",
    "!src/**/*.d.ts"
  ],
  coverageReporters: ["text", "lcov", "json-summary"],
  coverageThreshold: {
    global: {
      lines: 80,
      functions: 75,
      statements: 80
    },
    "./src/security/path-resolver.ts": {
      lines: 95,
      statements: 95
    },
    "./src/security/ip-utils.ts": {
      lines: 95,
      statements: 95
    },
    "./src/core/protocol-validator.ts": {
      lines: 90,
      statements: 90
    },
    "./src/security/policy-engine.ts": {
      lines: 90,
      statements: 90
    }
  },
  transform: {
    ...tsJestTransformCfg,
  },
};