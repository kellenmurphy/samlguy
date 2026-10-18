import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'jsdom',
        include: ['src/lib/**/*.test.ts', 'src/routes/**/*.test.ts'],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'lcov'],
            include: ['src/lib/**/*.ts', 'src/routes/**/*.ts'],
            exclude: [
                'src/lib/**/*.test.ts',
                'src/lib/fixtures.test-helper.ts',
                'src/routes/**/*.test.ts',
                'src/routes/**/*.svelte'
            ]
        }
    }
});
