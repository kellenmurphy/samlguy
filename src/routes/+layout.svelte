<script lang="ts">
    import '../app.css';
    import { onMount } from 'svelte';
    import { version } from '$app/environment';
    import type { Snippet } from 'svelte';

    let { children }: { children: Snippet } = $props();

    let isDark = $state(false);

    onMount(() => {
        isDark = document.documentElement.classList.contains('dark');

        const mq = window.matchMedia('(prefers-color-scheme: dark)');
        const handler = (e: MediaQueryListEvent) => {
            if (!localStorage.getItem('theme')) {
                isDark = e.matches;
                document.documentElement.classList.toggle('dark', e.matches);
            }
        };
        mq.addEventListener('change', handler);
        return () => mq.removeEventListener('change', handler);
    });

    function toggleTheme() {
        isDark = !isDark;
        document.documentElement.classList.toggle('dark', isDark);
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
    }
</script>

<svelte:head>
    <title>samlguy.com — Identity Decoder</title>
    <meta
        name="description"
        content="Paste any SAML assertion or JWT and get a clean, instant decode. The identity decoder built for the IAM community."
    />
</svelte:head>

<div
    class="flex min-h-screen flex-col bg-white text-neutral-900 dark:bg-neutral-950 dark:text-neutral-100"
>
    <header class="px-6 py-4">
        <div class="mx-auto flex max-w-5xl items-center justify-between">
            <a href="/" class="font-mono text-base font-semibold tracking-tight"
                >&lt;<span class="text-neutral-500 dark:text-neutral-500">saml:</span>Guy/&gt;</a
            >
            <button
                onclick={toggleTheme}
                aria-label="Toggle theme"
                class="rounded-md p-1.5 text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-700 dark:text-neutral-400 dark:hover:bg-neutral-800 dark:hover:text-neutral-200"
            >
                {#if isDark}
                    <svg
                        xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        class="h-4 w-4"
                    >
                        <circle cx="12" cy="12" r="5" />
                        <line x1="12" y1="1" x2="12" y2="3" />
                        <line x1="12" y1="21" x2="12" y2="23" />
                        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                        <line x1="1" y1="12" x2="3" y2="12" />
                        <line x1="21" y1="12" x2="23" y2="12" />
                        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                        <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
                    </svg>
                {:else}
                    <svg
                        xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="2"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        class="h-4 w-4"
                    >
                        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                    </svg>
                {/if}
            </button>
        </div>
    </header>

    <main class="mx-auto w-full max-w-5xl grow px-6 py-10">
        {@render children()}
    </main>

    <footer class="px-6 py-4">
        <div class="mx-auto flex max-w-5xl flex-col items-center gap-y-1 text-[10px] text-neutral-400 dark:text-neutral-600">
            <span>Made with ♥ by <a href="https://kellenmurphy.com" class="transition-colors hover:text-neutral-600 dark:hover:text-neutral-400">The SAML Guy</a></span>
            <div class="flex items-center gap-x-3">
                <a href="/privacy" class="transition-colors hover:text-neutral-600 dark:hover:text-neutral-400">Privacy</a>
                <span aria-hidden="true">&middot;</span>
                <a
                    href="https://github.com/kellenmurphy/samlguy/security"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="transition-colors hover:text-neutral-600 dark:hover:text-neutral-400"
                    >Security</a
                >
                <span aria-hidden="true">&middot;</span>
                <a
                    href="https://github.com/kellenmurphy/samlguy/releases/tag/samlguy-v{version}"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="font-mono transition-colors hover:text-neutral-600 dark:hover:text-neutral-400"
                    >v{version}</a
                >
                <span aria-hidden="true">&middot;</span>
                <a
                    href="https://github.com/kellenmurphy/samlguy"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="transition-colors hover:text-neutral-600 dark:hover:text-neutral-400"
                    >Source</a
                >
                <span aria-hidden="true">&middot;</span>
                <a
                    href="https://github.com/kellenmurphy/samlguy/blob/main/LICENSE"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="transition-colors hover:text-neutral-600 dark:hover:text-neutral-400"
                    >MIT License</a
                >
            </div>
        </div>
    </footer>
</div>
