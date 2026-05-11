import js from '@eslint/js';
import svelte from 'eslint-plugin-svelte';
import globals from 'globals';
import ts from 'typescript-eslint';

export default ts.config(
    js.configs.recommended,
    ...ts.configs.recommended,
    ...svelte.configs['flat/recommended'],
    {
        languageOptions: {
            globals: {
                ...globals.browser,
                ...globals.node
            }
        }
    },
    {
        files: ['**/*.svelte'],
        languageOptions: {
            parserOptions: {
                parser: ts.parser
            }
        }
    },
    {
        // samlguy.com is always deployed at root with no base path, so plain href="/" is correct
        rules: {
            'svelte/no-navigation-without-resolve': ['error', { ignoreLinks: true }]
        }
    },
    {
        ignores: ['build/', '.svelte-kit/', 'dist/']
    }
);
