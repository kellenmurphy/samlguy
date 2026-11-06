<script lang="ts">
    import type { CertInfo } from '#lib/cert.ts';
    import { isExpired, relativeLabel } from '#lib/time.ts';

    let {
        certificate,
        info
    }: {
        /** The certificate as base64 DER, as found in ds:X509Certificate or x5c. */
        certificate: string;
        /** Parsed details: undefined while decoding, false if decoding failed. */
        info: CertInfo | false | undefined;
    } = $props();

    let pem = $state<string | null>(null);
    let pemOpen = $state(false);
    let copied = $state<'cert' | 'key' | null>(null);
    let copyError = $state<string | null>(null);
    let copiedTimer: ReturnType<typeof setTimeout> | undefined;

    async function certPem(): Promise<string> {
        if (pem === null) {
            const { toPem } = await import('#lib/pem.ts');
            pem = toPem(certificate, 'CERTIFICATE');
        }
        return pem;
    }

    async function publicKeyPem(): Promise<string> {
        const [{ toPem }, { certPublicKeySpki }] = await Promise.all([
            import('#lib/pem.ts'),
            import('#lib/cert.ts')
        ]);
        return toPem(certPublicKeySpki(certificate), 'PUBLIC KEY');
    }

    async function copy(which: 'cert' | 'key') {
        copyError = null;
        try {
            await navigator.clipboard.writeText(
                which === 'cert' ? await certPem() : await publicKeyPem()
            );
            copied = which;
            clearTimeout(copiedTimer);
            copiedTimer = setTimeout(() => (copied = null), 2000);
        } catch {
            copyError = which === 'cert' ? 'Could not copy PEM' : 'Could not extract public key';
        }
    }

    async function togglePem() {
        if (!pemOpen) await certPem();
        pemOpen = !pemOpen;
    }

    // a different certificate in the same slot starts from a clean state
    $effect(() => {
        void certificate;
        pem = null;
        pemOpen = false;
        copied = null;
        copyError = null;
    });

    const btn =
        'rounded px-2 py-0.5 text-xs text-neutral-400 ring-1 ring-neutral-300 transition-colors hover:bg-neutral-100 hover:text-neutral-600 dark:ring-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300';
</script>

{#if info === false}
    <span class="text-sm text-neutral-500">present (could not decode)</span>
{:else if info}
    <div class="flex flex-wrap gap-2">
        <span
            class="rounded px-1.5 py-0.5 font-mono text-xs {info.isValid
                ? 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-400'
                : 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-400'}"
            >{info.isValid ? 'Valid' : 'Expired'}</span
        >
        <span
            class="rounded bg-neutral-200 px-1.5 py-0.5 font-mono text-xs text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300"
            >{info.keyAlgorithm}</span
        >
    </div>
    <div class="font-mono text-xs text-neutral-700 dark:text-neutral-300">
        {info.subject}
    </div>
    <div class="font-mono text-xs text-neutral-500">
        Issuer: {info.issuer}
    </div>
    <div class="text-xs text-neutral-500">
        {info.validFrom.toISOString().slice(0, 10)} →
        {info.validTo.toISOString().slice(0, 10)}
        <span
            class="ml-1 {isExpired(info.validTo)
                ? 'text-red-600 dark:text-red-400'
                : 'text-green-700 dark:text-green-400'}">({relativeLabel(info.validTo)})</span
        >
    </div>
{:else}
    <span class="text-sm text-neutral-500">decoding…</span>
{/if}

<div class="flex flex-wrap items-center gap-2 pt-0.5">
    <button type="button" class={btn} onclick={() => copy('cert')}
        >{copied === 'cert' ? 'Copied!' : 'Copy PEM'}</button
    >
    {#if info}
        <button type="button" class={btn} onclick={() => copy('key')}
            >{copied === 'key' ? 'Copied!' : 'Copy public key'}</button
        >
    {/if}
    <button type="button" class={btn} aria-expanded={pemOpen} onclick={togglePem}
        >{pemOpen ? 'Hide PEM' : 'Show PEM'}</button
    >
    {#if copyError}
        <span class="text-xs text-red-600 dark:text-red-400">{copyError}</span>
    {/if}
</div>
{#if pemOpen && pem}
    <pre
        class="max-w-full overflow-x-auto rounded bg-neutral-100 p-2 font-mono text-[11px] leading-snug text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300">{pem}</pre>
{/if}
