import adapter from '@sveltejs/adapter-cloudflare';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import { readFileSync } from 'node:fs';

// Read the package version at build time so the footer always reflects the released
// version. release-please bumps package.json on each release, so this updates automatically.
const { version } = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf-8'));

export default {
    preprocess: vitePreprocess(),
    kit: {
        adapter: adapter(),
        version: { name: version },
        csp: {
            mode: 'hash',
            directives: {
                'default-src': ['self'],
                'script-src': ['self', 'sha256-tQByV08yFR2Qu6IDiPNAOwdmQmbdiJs0AWzOhHN9fV0='],
                'style-src': ['self'],
                'img-src': ['self'],
                'connect-src': ['self'],
                'font-src': ['none'],
                'object-src': ['none'],
                'base-uri': ['self'],
                'form-action': ['self'],
                'upgrade-insecure-requests': true,
                'frame-ancestors': ['none']
            }
        }
    }
};
