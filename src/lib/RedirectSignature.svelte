<script lang="ts">
    import {
        parseRedirectKeys,
        parseSignedRedirect,
        SIG_ALGS,
        verifyRedirect,
        type RedirectVerifyResult,
        type SignedRedirect
    } from '#lib/redirect-sig.ts';
    import InfoTip from '#lib/InfoTip.svelte';

    let { query, issuer }: { query: string; issuer?: string } = $props();

    const parsed = $derived.by((): { signed: SignedRedirect | null; error: string | null } => {
        try {
            return { signed: parseSignedRedirect(query), error: null };
        } catch (e) {
            return { signed: null, error: e instanceof Error ? e.message : 'Unreadable signature' };
        }
    });
    const alg = $derived(parsed.signed ? SIG_ALGS[parsed.signed.sigAlg] : undefined);

    let keyText = $state('');
    let result = $state<RedirectVerifyResult | null>(null);
    let keyError = $state<string | null>(null);
    let generation = 0;

    // a different message starts from a clean result
    $effect(() => {
        void query;
        generation++;
        result = null;
        keyError = null;
    });

    async function verify() {
        if (!parsed.signed) return;
        const gen = ++generation;
        keyError = null;
        result = null;
        let keys;
        try {
            keys = parseRedirectKeys(keyText);
        } catch (e) {
            keyError = e instanceof Error ? e.message : 'Could not read the key';
            return;
        }
        const r = await verifyRedirect(parsed.signed, keys);
        if (gen === generation) result = r;
    }

    const STYLE: Record<RedirectVerifyResult['status'], string> = {
        valid: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-400',
        invalid: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-400',
        'no-key': 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-400',
        unsupported: 'bg-neutral-200 text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300'
    };
    const LABEL: Record<RedirectVerifyResult['status'], string> = {
        valid: 'Verified',
        invalid: 'Invalid signature',
        'no-key': 'No matching key',
        unsupported: 'Cannot verify'
    };

    const btn =
        'rounded px-2 py-0.5 text-xs text-neutral-400 ring-1 ring-neutral-300 transition-colors hover:bg-neutral-100 hover:text-neutral-600 disabled:opacity-50 dark:ring-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300';
</script>

<div
    class="overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-900"
>
    <div class="border-b border-neutral-200 px-4 py-2.5 dark:border-neutral-800">
        <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500"
            >Redirect Signature<InfoTip key="saml.redirectSignature" /></span
        >
    </div>
    <div class="space-y-2.5 px-4 py-3">
        {#if parsed.error}
            <div class="text-xs text-red-600 dark:text-red-400">{parsed.error}</div>
        {:else if parsed.signed}
            <div class="flex flex-wrap items-center gap-2 text-xs">
                <span class="text-neutral-500">SigAlg</span>
                <span
                    class="rounded px-1.5 py-0.5 font-mono {alg?.deprecated
                        ? 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-400'
                        : 'bg-neutral-200 text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300'}"
                    title={parsed.signed.sigAlg}>{alg?.label ?? parsed.signed.sigAlg}</span
                >
                {#if alg?.deprecated}<span class="text-amber-700 dark:text-amber-400"
                        >SHA-1 is deprecated</span
                    >{/if}
            </div>
            <textarea
                bind:value={keyText}
                rows="4"
                spellcheck="false"
                placeholder={`SP metadata${issuer ? ` for ${issuer}` : ''}, a CERTIFICATE or PUBLIC KEY PEM, or the base64 from ds:X509Certificate`}
                class="w-full rounded border border-neutral-300 bg-white p-2 font-mono text-xs text-neutral-800 dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-200"
            ></textarea>
            <div class="flex flex-wrap items-center gap-2">
                <button type="button" class={btn} disabled={keyText.trim() === ''} onclick={verify}
                    >Verify</button
                >
                {#if keyError}
                    <span class="text-xs text-red-600 dark:text-red-400">{keyError}</span>
                {/if}
                {#if result}
                    <span class="rounded px-1.5 py-0.5 text-xs font-medium {STYLE[result.status]}"
                        >{LABEL[result.status]}</span
                    >
                    <span class="text-xs text-neutral-500"
                        >{result.detail}{result.status === 'valid' && result.key
                            ? ` with the ${result.key.label}`
                            : ''}</span
                    >
                {/if}
            </div>
        {/if}
    </div>
</div>
