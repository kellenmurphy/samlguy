<script lang="ts">
    import type { CandidateKey, VerifyResult } from '#lib/jws.ts';

    let {
        token,
        header,
        issuer
    }: {
        /** The compact JWS, Bearer prefix already stripped. */
        token: string;
        header: Record<string, unknown>;
        /** The iss claim, when the token has one. */
        issuer: string | null;
    } = $props();

    const alg = $derived(typeof header.alg === 'string' ? header.alg : '');
    const unsigned = $derived(alg === '' || alg.toLowerCase() === 'none');
    const hmac = $derived(/^HS(256|384|512)$/.test(alg));
    const hasX5c = $derived(Array.isArray(header.x5c) && typeof header.x5c[0] === 'string');

    let result = $state<VerifyResult | null>(null);
    let sourceLabel = $state('');
    let busy = $state(false);
    let fetchError = $state<string | null>(null);
    let jwks = $state<{ uri: string; keys: CandidateKey[]; total: number } | null>(null);
    let pasteOpen = $state(false);
    let pasted = $state('');
    let pasteError = $state<string | null>(null);
    let copiedKey = $state<number | null>(null);
    let generation = 0;

    // a different token starts from a clean slate
    $effect(() => {
        void token;
        generation++;
        result = null;
        sourceLabel = '';
        busy = false;
        fetchError = null;
        jwks = null;
        pasteError = null;
        copiedKey = null;
    });

    async function run(keys: CandidateKey[], label: string, gen: number) {
        const { verifyJwt } = await import('#lib/jws.ts');
        const r = await verifyJwt(token, keys);
        if (gen !== generation) return;
        result = r;
        sourceLabel = label;
    }

    async function verifyWithJwks() {
        if (!issuer) return;
        const gen = ++generation;
        busy = true;
        fetchError = null;
        result = null;
        try {
            const res = await fetch(`/api/jwks?issuer=${encodeURIComponent(issuer)}`);
            if (gen !== generation) return;
            if (!res.ok) {
                const body = (await res.json().catch(() => null)) as { message?: string } | null;
                fetchError = `Could not fetch the JWKS: ${body?.message ?? `HTTP ${res.status}`}`;
                return;
            }
            const data = (await res.json()) as { jwks_uri: string; keys: unknown[] };
            const { keysFromJwks } = await import('#lib/jws.ts');
            const keys = keysFromJwks(data.keys, 'jwks');
            if (gen !== generation) return;
            jwks = { uri: data.jwks_uri, keys, total: data.keys.length };
            await run(keys, 'the issuer JWKS', gen);
        } catch {
            if (gen === generation) fetchError = 'Could not reach the JWKS proxy';
        } finally {
            if (gen === generation) busy = false;
        }
    }

    async function verifyWithX5c() {
        const gen = ++generation;
        const { keysFromX5c } = await import('#lib/jws.ts');
        await run(keysFromX5c(header), 'the x5c certificate', gen);
    }

    async function verifyWithPasted() {
        const gen = ++generation;
        pasteError = null;
        const { parseKeyInput } = await import('#lib/jws.ts');
        let keys: CandidateKey[];
        try {
            keys = parseKeyInput(pasted);
        } catch (e) {
            pasteError = e instanceof Error ? e.message : 'Could not read the key';
            return;
        }
        await run(keys, 'the pasted key', gen);
    }

    async function copyKeyPem(key: CandidateKey) {
        const { toPem } = await import('#lib/pem.ts');
        try {
            await navigator.clipboard.writeText(toPem(key.spki, 'PUBLIC KEY'));
            copiedKey = key.index;
            setTimeout(() => {
                if (copiedKey === key.index) copiedKey = null;
            }, 2000);
        } catch {
            // clipboard refused; the PEM is still available from the JWKS itself
        }
    }

    function describeKey(k: CandidateKey): string {
        const kty = typeof k.jwk?.kty === 'string' ? k.jwk.kty : '?';
        const crv = typeof k.jwk?.crv === 'string' ? ` ${k.jwk.crv}` : '';
        return `${kty}${crv}`;
    }

    const STATUS_STYLE: Record<VerifyResult['status'], string> = {
        valid: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-400',
        invalid: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-400',
        'no-key': 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-400',
        unsupported: 'bg-neutral-200 text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300',
        unsigned: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-400'
    };

    const STATUS_LABEL: Record<VerifyResult['status'], string> = {
        valid: 'Verified',
        invalid: 'Invalid signature',
        'no-key': 'No matching key',
        unsupported: 'Cannot verify',
        unsigned: 'Unsigned'
    };

    const btn =
        'rounded px-2 py-0.5 text-xs text-neutral-400 ring-1 ring-neutral-300 transition-colors hover:bg-neutral-100 hover:text-neutral-600 disabled:opacity-50 dark:ring-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300';
</script>

{#if unsigned}
    <span class="rounded px-1.5 py-0.5 text-xs font-medium {STATUS_STYLE.unsigned}">Unsigned</span>
    <span class="ml-2 text-xs text-neutral-500">alg "none" carries no signature to verify</span>
{:else if hmac}
    <span class="rounded px-1.5 py-0.5 text-xs font-medium {STATUS_STYLE.unsupported}"
        >Cannot verify</span
    >
    <span class="ml-2 text-xs text-neutral-500"
        >{alg} is verified with a shared secret, not a public key</span
    >
{:else}
    <div class="space-y-2">
        <div class="flex flex-wrap items-center gap-2">
            {#if issuer}
                <button type="button" class={btn} disabled={busy} onclick={verifyWithJwks}
                    >{busy ? 'Fetching JWKS…' : 'Verify with issuer JWKS'}</button
                >
            {/if}
            {#if hasX5c}
                <button type="button" class={btn} onclick={verifyWithX5c}>Verify with x5c</button>
            {/if}
            <button
                type="button"
                class={btn}
                aria-expanded={pasteOpen}
                onclick={() => (pasteOpen = !pasteOpen)}
                >{pasteOpen ? 'Hide key' : 'Paste a key'}</button
            >
        </div>

        {#if pasteOpen}
            <div class="space-y-1.5">
                <textarea
                    bind:value={pasted}
                    rows="4"
                    spellcheck="false"
                    placeholder="JWK, JWKS, or a PUBLIC KEY / CERTIFICATE PEM"
                    class="w-full rounded border border-neutral-300 bg-white p-2 font-mono text-xs text-neutral-800 dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-200"
                ></textarea>
                <div class="flex items-center gap-2">
                    <button
                        type="button"
                        class={btn}
                        disabled={pasted.trim() === ''}
                        onclick={verifyWithPasted}>Verify</button
                    >
                    {#if pasteError}
                        <span class="text-xs text-red-600 dark:text-red-400">{pasteError}</span>
                    {/if}
                </div>
            </div>
        {/if}

        {#if fetchError}
            <div class="text-xs text-red-600 dark:text-red-400">{fetchError}</div>
        {/if}

        {#if result}
            <div class="flex flex-wrap items-center gap-2">
                <span
                    class="rounded px-1.5 py-0.5 text-xs font-medium {STATUS_STYLE[result.status]}"
                    >{STATUS_LABEL[result.status]}</span
                >
                <span class="text-xs text-neutral-500">
                    {result.detail}{result.status === 'valid' ? ` with ${sourceLabel}` : ''}
                </span>
            </div>
            {#if result.status === 'valid' && result.key?.source === 'x5c'}
                <div class="text-xs text-amber-700 dark:text-amber-400">
                    The key came from the token itself. This proves the token was signed by that
                    certificate's key, not that the certificate is trusted; the chain is not
                    validated here.
                </div>
            {/if}
        {/if}

        {#if jwks}
            <div class="space-y-1">
                <div class="break-all text-xs text-neutral-500">
                    {jwks.keys.length} public key{jwks.keys.length === 1 ? '' : 's'} from
                    <span class="font-mono">{jwks.uri}</span>{jwks.total > jwks.keys.length
                        ? ` (${jwks.total - jwks.keys.length} without a usable public key skipped)`
                        : ''}
                </div>
                <ul class="space-y-1">
                    {#each jwks.keys as k (k.index)}
                        {@const signer =
                            result?.status === 'valid' &&
                            result.key?.source === 'jwks' &&
                            result.key.index === k.index}
                        <li class="flex flex-wrap items-center gap-2 font-mono text-xs">
                            <span
                                class="rounded px-1.5 py-0.5 {signer
                                    ? 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-400'
                                    : 'bg-neutral-200 text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300'}"
                                >{describeKey(k)}</span
                            >
                            <span class="text-neutral-700 dark:text-neutral-300"
                                >{k.kid ?? '(no kid)'}</span
                            >
                            {#if k.alg}<span class="text-neutral-500">{k.alg}</span>{/if}
                            {#if k.use}<span class="text-neutral-500">use={k.use}</span>{/if}
                            {#if signer}<span class="font-sans text-green-700 dark:text-green-400"
                                    >signed this token</span
                                >{/if}
                            <button
                                type="button"
                                class="{btn} font-sans"
                                onclick={() => copyKeyPem(k)}
                                >{copiedKey === k.index ? 'Copied!' : 'Copy PEM'}</button
                            >
                        </li>
                    {/each}
                </ul>
            </div>
        {/if}
    </div>
{/if}
