/**
 * Jest configuration for unit tests
 */

module.exports = {
  // Test environment
  testEnvironment: 'node',
  
  // Test file patterns
  testMatch: [
    '**/test/unit/**/*.test.js',
    '**/test/unit/**/*.spec.js'
  ],
  
  // Coverage settings
  collectCoverageFrom: [
    'output-servers/**/*.js',
    '!output-servers/**/*.test.js',
    '!output-servers/**/*.spec.js'
  ],
  
  // Module paths
  roots: ['<rootDir>'],
  
  // The output-servers modules and constants.js are ESM; babel-jest turns them
  // into CommonJS so the suites can require() the real implementation. The
  // preset is inline, not in a babel.config.js, because a project-wide babel
  // config would also be picked up by the webpack babel-loader.
  transform: {
    '\\.js$': ['babel-jest', { presets: [['@babel/preset-env', { targets: { node: 'current' } }]] }]
  },
  
  // Setup files
  setupFilesAfterEnv: [],
  
  // Ignore patterns
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/.test-profile/'
  ],
  
  // Verbose output
  verbose: true,
  
  // Coverage threshold (optional)
  coverageThreshold: {
    global: {
      statements: 70,
      branches: 60,
      functions: 70,
      lines: 70
    }
  },
  
  // Reporter options
  coverageReporters: ['text', 'lcov', 'html'],
  
  // Test timeout
  testTimeout: 10000
};

