export default {
    // Base configuration for all tests
    projects: [
        // Server-side tests configuration
        {
            displayName: 'backend',
            testEnvironment: 'node',
            transform: {},
            testMatch: ['<rootDir>/backend/tests/**/*.test.js'],
            moduleFileExtensions: ['js', 'mjs', 'json', 'node'],
            moduleNameMapping: {
                '^@/(.*)$': '<rootDir>/backend/src/$1',
                '^@controllers/(.*)$': '<rootDir>/backend/src/controllers/$1',
                '^@models/(.*)$': '<rootDir>/backend/src/models/$1',
                '^@utils/(.*)$': '<rootDir>/backend/src/utils/$1',
                '^@tests/(.*)$': '<rootDir>/backend/src/tests/$1'
            },
            setupFilesAfterEnv: ['./backend/src/tests/jest.setup.js'],
            coverageDirectory: '<rootDir>/backend/coverage',
            collectCoverageFrom: [
                'server/src/**/*.js',
                '!server/src/config/**',
                '!**/node_modules/**',
            ],
        },

        // Client-side tests configuration
        {
            displayName: 'frontend',
            testEnvironment: 'jsdom',
            testMatch: ['<rootDir>/frontend/src/**/*.test.{js,jsx}'],
            moduleFileExtensions: ['js', 'jsx', 'json'],
            moduleNameMapper: {
                '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
                '\\.(jpg|jpeg|png|gif|webp|svg)$': '<rootDir>/client/src/tests/__mocks__/fileMock.js',
            },
            setupFilesAfterEnv: ['<rootDir>/frontend/src/tests/jest.setup.js'],
            transform: {
                '^.+\\.(js|jsx)$': 'babel-jest',
            },
            coverageDirectory: '<rootDir>/frontend/coverage',
            collectCoverageFrom: [
                'client/src/**/*.{js,jsx}',
                '!client/src/index.js',
                '!**/node_modules/**',
            ],
        },
    ],

    // Global configuration
    verbose: true,
    collectCoverage: true,
    coverageReporters: ['text', 'lcov', 'clover', 'html'],
    coverageThreshold: {
        global: {
            statements: 70,
            branches: 60,
            functions: 70,
            lines: 70,
        },
    },
    testTimeout: 10000,
}