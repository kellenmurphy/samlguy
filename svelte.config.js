import adapter from '@sveltejs/adapter-cloudflare';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

export default {
    preprocess: vitePreprocess(),
    kit: {
        adapter: adapter(),
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
