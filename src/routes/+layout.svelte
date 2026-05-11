<script lang="ts">
    import '../app.css';
    import { onMount } from 'svelte';
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
            <a href="/" class="font-mono text-base font-semibold tracking-tight">
                <span class="text-neutral-500 dark:text-neutral-500">&lt;</span>samlguy.com<span
                    class="text-neutral-500 dark:text-neutral-500"
                >
                    /&gt;</span
                >
            </a>
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
        <div
            class="mx-auto flex max-w-5xl flex-col items-center gap-2 text-xs text-neutral-400 dark:text-neutral-600 sm:flex-row sm:flex-wrap sm:justify-center sm:gap-x-3 sm:gap-y-1"
        >
            <a
                href="/privacy"
                class="transition-colors hover:text-neutral-600 dark:hover:text-neutral-400"
                >Privacy</a
            >
            <span aria-hidden="true" class="hidden sm:inline">&middot;</span>
            <span>
                Made with ♥ by <a
                    href="https://kellenmurphy.com"
                    class="transition-colors hover:text-neutral-600 dark:hover:text-neutral-400"
                    >The SAML Guy</a
                >
            </span>
            <span aria-hidden="true" class="hidden sm:inline">&middot;</span>
            <span class="flex items-center gap-2">
                <a
                    href="https://github.com/kellenmurphy/samlguy"
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="GitHub repository"
                >
                    <svg
                        viewBox="0 0 16 16"
                        fill="currentColor"
                        class="h-4 w-4 text-neutral-900 dark:text-neutral-100"
                        aria-hidden="true"
                    >
                        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
                    </svg>
                </a>
                <a
                    href="https://github.com/kellenmurphy/samlguy/actions/workflows/ci.yml"
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="CI status"
                >
                    <img
                        src="https://img.shields.io/github/actions/workflow/status/kellenmurphy/samlguy/ci.yml?branch=main&style=flat-square&label=CI&labelColor=404040"
                        alt="CI status"
                        class="h-4"
                    />
                </a>
                <a
                    href="https://app.codecov.io/gh/kellenmurphy/samlguy"
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label="Code coverage"
                >
                    <img
                        src="https://img.shields.io/codecov/c/github/kellenmurphy/samlguy?style=flat-square&label=coverage&labelColor=404040"
                        alt="Code coverage"
                        class="h-4"
                    />
                </a>
            </span>
        </div>
    </footer>
</div>
