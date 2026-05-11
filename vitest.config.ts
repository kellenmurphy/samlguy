import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
    resolve: {
        alias: {
            $lib: path.resolve('./src/lib')
        }
    },
    test: {
        environment: 'jsdom',
        include: ['src/lib/**/*.test.ts'],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'lcov'],
            include: ['src/lib/**/*.ts'],
            exclude: ['src/lib/**/*.test.ts', 'src/lib/fixtures.test-helper.ts']
        }
    }
});
