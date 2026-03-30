/** @type {import('jest').Config} */
module.exports = {
    testEnvironment: 'node',
    roots: ['<rootDir>/__tests__'],
    testMatch: ['**/*.test.ts'],
    transform: {
        '^.+\.tsx?$': [
            '@swc/jest',
            {
                jsc: { parser: { syntax: 'typescript' } },
                module: { type: 'es6' },
            },
        ],
    },
    extensionsToTreatAsEsm: ['.ts'],
};
