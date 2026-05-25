<script lang="ts">
    import { onMount } from 'svelte';
    import { decodeSaml, decodeAllSaml, type SamlDecodeResult, AUTHN_CONTEXT_LABELS, AUTHN_CONTEXT_SPEC_URLS, STATUS_DESCRIPTIONS, STATUS_SPEC_URLS } from '$lib/saml';
    import { decodeJwt, type JwtDecodeResult } from '$lib/jwt';
    import { decodeAllGeneric, type GenericDecodeResult } from '$lib/generic';
    import InfoTip from '$lib/InfoTip.svelte';
    import { SAML_TS_KEY } from '$lib/explanations';
    import { encodePayload, decodePayload } from '$lib/hash';
    import { getAttributeInfo, eppnScopedStatus } from '$lib/attributes';
    import { relativeLabel, isExpired } from '$lib/time';
    import type { CertInfo } from '$lib/cert';
    import { highlightXml, XML_ELEMENT_TIPS } from '$lib/xml-highlight';
    import { EXAMPLES, EXAMPLE_CATEGORIES } from '$lib/examples';

    type InputType = 'saml' | 'jwt' | null;

    let input = $state('');
    let results = $state<SamlDecodeResult[]>([]);
    let genericResults = $state<GenericDecodeResult[]>([]);
    let decodeError = $state<string | null>(null);
    // keyed by first 20 chars of cert base64; false = decode attempted but failed
    let certInfos = $state<Record<string, CertInfo | false>>({});
    let samlCopiedIdx = $state(-1);
    let genericCopiedIdx = $state(-1);
    let jwtResult = $state<JwtDecodeResult | null>(null);
    let jwtCopied = $state(false);
    let linkCopied = $state(false);
    let discoveryResult = $state<Record<string, unknown> | null>(null);
    let discoveryLoading = $state(false);
    let discoveryError = $state<string | null>(null);
    let discoveryGeneration = 0;
    let showExamples = $state(false);
    let examplesRef: HTMLElement | undefined;

    $effect(() => {
        if (!showExamples) return;
        const handleClick = (e: MouseEvent) => {
            if (!examplesRef?.contains(e.target as Node)) {
                showExamples = false;
            }
        };
        document.addEventListener('mousedown', handleClick);
        return () => document.removeEventListener('mousedown', handleClick);
    });

    const discoveryIssuerMatch = $derived.by(() => {
        if (!discoveryResult || !jwtResult) return null;
        const d = discoveryResult.issuer;
        const t = jwtResult.payload.iss;
        if (typeof d !== 'string' || typeof t !== 'string') return null;
        return d === t;
    });

    const discoveryAlgOk = $derived.by(() => {
        if (!discoveryResult || !jwtResult) return null;
        const algs = discoveryResult.id_token_signing_alg_values_supported;
        if (!Array.isArray(algs)) return null;
        const tokenAlg = typeof jwtResult.header.alg === 'string' ? jwtResult.header.alg : null;
        if (!tokenAlg) return null;
        return algs.some((a) => a === tokenAlg);
    });

    function detect(value: string): InputType {
        const t = value.trim();
        if (!t) return null;
        if (/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$/.test(t)) return 'jwt';
        if (/^Authorization:\s*Bearer\s+/i.test(t)) return 'jwt';
        return 'saml';
    }

    const detected = $derived(detect(input));
    const hasResults = $derived(!!(results.length || genericResults.length || jwtResult));

    onMount(() => {
        const hash = window.location.hash.slice(1);
        if (hash) {
            try {
                input = decodePayload(hash);
            } catch {
                // ignore malformed hash
            }
        }
    });

    $effect(() => {
        const value = input.trim();

        if (!value) {
            results = [];
            genericResults = [];
            jwtResult = null;
            decodeError = null;
            discoveryResult = null;
            discoveryError = null;
            discoveryLoading = false;
            discoveryGeneration++;
            return;
        }

        if (detected === 'jwt') {
            results = [];
            genericResults = [];
            decodeError = null;
            discoveryResult = null;
            discoveryError = null;
            discoveryLoading = false;
            discoveryGeneration++;
            const timer = setTimeout(() => {
                try {
                    jwtResult = decodeJwt(value);
                } catch (e) {
                    jwtResult = null;
                    decodeError = e instanceof Error ? e.message : 'Could not decode JWT';
                }
            }, 300);
            return () => clearTimeout(timer);
        }

        jwtResult = null;
        discoveryResult = null;
        discoveryError = null;
        discoveryLoading = false;
        discoveryGeneration++;

        const timer = setTimeout(() => {
            // If the input contains multiple SAML messages, show them all
            const multiSaml = decodeAllSaml(value);
            if (multiSaml.length > 1) {
                results = multiSaml;
                genericResults = [];
                decodeError = null;
                return;
            }

            // Single-message path: handles raw blobs without SAMLRequest= prefix
            let singleError!: string | null;
            try {
                results = [decodeSaml(value)];
                genericResults = [];
                decodeError = null;
                return;
            } catch (e) {
                results = [];
                singleError = e instanceof Error ? e.message : 'Could not decode input';
            }

            // Generic fallback: decode whatever base64/XML/JSON we can find
            const genResults = decodeAllGeneric(value);
            if (genResults.length > 0) {
                genericResults = genResults;
                decodeError = null;
            } else {
                genericResults = [];
                decodeError = singleError;
            }
        }, 300);

        return () => clearTimeout(timer);
    });

    $effect(() => {
        for (const r of results) {
            const raw = r.summary.signingCertificate;
            if (!raw) continue;
            const key = raw.slice(0, 20);
            if (key in certInfos) continue;
            import('$lib/cert')
                .then(({ decodeCert }) => {
                    try {
                        certInfos = { ...certInfos, [key]: decodeCert(raw) };
                    } catch {
                        certInfos = { ...certInfos, [key]: false };
                    }
                })
                .catch(() => {
                    certInfos = { ...certInfos, [key]: false };
                });
        }
    });

    const NAME_ID_FORMATS: Record<string, string> = {
        'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress': 'emailAddress',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent': 'persistent',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:transient': 'transient',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified': 'unspecified',
        'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName': 'X509SubjectName',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos': 'kerberos',
        'urn:oasis:names:tc:SAML:2.0:nameid-format:entity': 'entity'
    };

    function shortFormat(format?: string): string {
        return format ? (NAME_ID_FORMATS[format] ?? format) : 'unspecified';
    }

    const STATUS_PREFIX = 'urn:oasis:names:tc:SAML:2.0:status:';
    function shortCode(urn: string): string {
        return urn.startsWith(STATUS_PREFIX) ? urn.slice(STATUS_PREFIX.length) : urn;
    }

    let xmlTip = $state<{ el: string; text: string; x: number; y: number } | null>(null);

    function handleXmlMouseover(e: MouseEvent) {
        const target = (e.target as Element).closest('[data-el]');
        if (!target) { xmlTip = null; return; }
        const local = target.getAttribute('data-el')!;
        const tip = XML_ELEMENT_TIPS[local];
        if (!tip) { xmlTip = null; return; }
        const rect = target.getBoundingClientRect();
        xmlTip = { el: local, text: tip, x: rect.left, y: rect.bottom + 6 };
    }

    function handleXmlMouseleave() {
        xmlTip = null;
    }

    async function copySamlXml(idx: number) {
        const r = results[idx];
        if (!r) return;
        await navigator.clipboard.writeText(r.xml);
        samlCopiedIdx = idx;
        setTimeout(() => (samlCopiedIdx = -1), 2000);
    }

    async function copyGenericContent(idx: number) {
        const r = genericResults[idx];
        if (!r) return;
        await navigator.clipboard.writeText(r.content);
        genericCopiedIdx = idx;
        setTimeout(() => (genericCopiedIdx = -1), 2000);
    }

    async function copyJwt() {
        if (!jwtResult) return;
        await navigator.clipboard.writeText(jwtResult.raw);
        jwtCopied = true;
        setTimeout(() => (jwtCopied = false), 2000);
    }

    async function copyLink() {
        const encoded = encodePayload(input.trim());
        const url = `${window.location.origin}${window.location.pathname}#${encoded}`;
        await navigator.clipboard.writeText(url);
        linkCopied = true;
        setTimeout(() => (linkCopied = false), 2000);
    }

    async function fetchDiscovery() {
        const iss =
            jwtResult && typeof jwtResult.payload.iss === 'string' ? jwtResult.payload.iss : null;
        if (!iss) return;
        const gen = ++discoveryGeneration;
        discoveryLoading = true;
        discoveryError = null;
        discoveryResult = null;
        try {
            const res = await fetch(`/api/discover?issuer=${encodeURIComponent(iss)}`);
            if (gen !== discoveryGeneration) return;
            if (!res.ok) {
                discoveryError = `Discovery failed (HTTP ${res.status})`;
            } else {
                discoveryResult = (await res.json()) as Record<string, unknown>;
            }
        } catch (e) {
            if (gen !== discoveryGeneration) return;
            discoveryError = e instanceof Error ? e.message : 'Could not reach discovery endpoint';
        } finally {
            if (gen === discoveryGeneration) discoveryLoading = false;
        }
    }

    function safeHref(url: string | null): string | null {
        if (!url) return null;
        try {
            return new URL(url).protocol === 'https:' ? url : null;
        } catch {
            return null;
        }
    }

    const ENCODING_LABELS: Record<string, string> = {
        'base64+deflate': 'base64 + DEFLATE',
        base64: 'base64',
        text: 'plain text'
    };
</script>

<div class="space-y-8">
    <div class="flex items-start justify-between gap-4">
        <div>
            <h1 class="text-2xl font-bold">Identity Decoder</h1>
            <p class="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
                Paste a SAML assertion, JWT, query string, URL, or HTTP log line. We'll figure it out and try to explain it!
            </p>
        </div>
        <div bind:this={examplesRef} class="relative flex shrink-0 items-center gap-2">
            <button
                onclick={() => (showExamples = !showExamples)}
                class="flex items-center gap-1 rounded-md px-3 py-1.5 text-sm text-neutral-500 ring-1 ring-neutral-300 transition-colors hover:bg-neutral-100 hover:text-neutral-700 dark:ring-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300"
            >
                Examples
                <svg
                    xmlns="http://www.w3.org/2000/svg"
                    viewBox="0 0 20 20"
                    fill="currentColor"
                    class="h-4 w-4 transition-transform {showExamples ? 'rotate-180' : ''}"
                    aria-hidden="true"
                >
                    <path
                        fill-rule="evenodd"
                        d="M5.23 7.21a.75.75 0 011.06.02L10 11.168l3.71-3.938a.75.75 0 111.08 1.04l-4.25 4.5a.75.75 0 01-1.08 0l-4.25-4.5a.75.75 0 01.02-1.06z"
                        clip-rule="evenodd"
                    />
                </svg>
            </button>
            {#if hasResults}
                <button
                    onclick={copyLink}
                    class="rounded-md px-3 py-1.5 text-sm text-neutral-500 ring-1 ring-neutral-300 transition-colors hover:bg-neutral-100 hover:text-neutral-700 dark:ring-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300"
                >{linkCopied ? 'Copied!' : 'Copy link'}</button>
            {/if}
            {#if showExamples}
                <div class="absolute right-0 top-full z-20 mt-1 min-w-60 overflow-hidden rounded-lg border border-neutral-200 bg-white shadow-lg dark:border-neutral-700 dark:bg-neutral-900">
                    {#each EXAMPLE_CATEGORIES as category, i (category)}
                        {@const catExamples = EXAMPLES.filter((e) => e.category === category)}
                        {#if catExamples.length > 0}
                            {#if i > 0}
                                <div class="border-t border-neutral-100 dark:border-neutral-800"></div>
                            {/if}
                            <div class="px-3 pb-0.5 pt-2">
                                <p class="text-xs font-semibold uppercase tracking-wider text-neutral-400 dark:text-neutral-500">{category}</p>
                            </div>
                            {#each catExamples as example (example.label)}
                                <button
                                    onclick={() => {
                                        input = example.payload();
                                        showExamples = false;
                                    }}
                                    class="block w-full px-3 py-1.5 text-left text-sm text-neutral-700 hover:bg-neutral-50 dark:text-neutral-300 dark:hover:bg-neutral-800"
                                >{example.label}</button>
                            {/each}
                            <div class="pb-1"></div>
                        {/if}
                    {/each}
                </div>
            {/if}
        </div>
    </div>

    <textarea
        id="input"
        bind:value={input}
        placeholder="Paste anything — SAMLRequest, SAMLResponse, JWT, Authorization header, query string, full URL..."
        class="h-48 w-full resize-y rounded-lg border border-neutral-300 bg-neutral-50 px-4 py-3 font-mono text-sm text-neutral-900 placeholder-neutral-400 focus:border-neutral-500 focus:outline-none dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100 dark:placeholder-neutral-600"
    ></textarea>

    <p class="flex items-center gap-1.5 text-xs text-neutral-400 dark:text-neutral-600">
        <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            class="h-3 w-3 shrink-0"
            aria-hidden="true"
        >
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
        Decoded entirely in your browser — nothing you paste is sent to any server.
    </p>

    {#if jwtResult}
        {@const alg = typeof jwtResult.header.alg === 'string' ? jwtResult.header.alg : 'none'}
        {@const typ = typeof jwtResult.header.typ === 'string' ? jwtResult.header.typ : null}
        {@const kid = typeof jwtResult.header.kid === 'string' ? jwtResult.header.kid : null}
        {@const iss = typeof jwtResult.payload.iss === 'string' ? jwtResult.payload.iss : null}
        {@const sub = typeof jwtResult.payload.sub === 'string' ? jwtResult.payload.sub : null}
        {@const jti = typeof jwtResult.payload.jti === 'string' ? jwtResult.payload.jti : null}
        {@const audArr = jwtResult.payload.aud !== undefined
            ? Array.isArray(jwtResult.payload.aud)
                ? jwtResult.payload.aud
                : [jwtResult.payload.aud]
            : null}
        {@const hasTimestamps = !!(
            jwtResult.timestamps.iat ||
            jwtResult.timestamps.exp ||
            jwtResult.timestamps.nbf
        )}

        {#if jwtResult.isAlgNone || jwtResult.isWeakAlg}
            <div
                class="rounded-lg border px-4 py-3 text-sm {jwtResult.isAlgNone
                    ? 'border-red-300 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950/30 dark:text-red-400'
                    : 'border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-400'}"
            >
                {#if jwtResult.isAlgNone}
                    <strong>Dangerous:</strong> <code>alg: none</code> — this token has no signature
                    and cannot be trusted.
                {:else}
                    <strong>Weak algorithm:</strong>
                    <code>{alg}</code> uses a shared secret (HMAC). Signature cannot be verified without
                    the secret key.
                {/if}
            </div>
        {/if}

        <!-- Summary -->
        <div
            class="overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-900"
        >
            <div class="border-b border-neutral-200 px-4 py-2.5 dark:border-neutral-800">
                <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500"
                    >Summary</span
                >
            </div>
            <dl class="divide-y divide-neutral-100 dark:divide-neutral-800">
                <div class="flex gap-4 px-4 py-2.5">
                    <dt class="w-36 shrink-0 text-sm text-neutral-500">Algorithm<InfoTip key="jwt.algorithm" /></dt>
                    <dd class="flex flex-wrap items-center gap-2">
                        <span
                            class="rounded bg-neutral-200 px-1.5 py-0.5 font-mono text-xs text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300"
                        >
                            {alg}
                        </span>
                        {#if jwtResult.isAlgNone}
                            <span
                                class="rounded bg-red-100 px-1.5 py-0.5 text-xs font-medium text-red-800 dark:bg-red-900/40 dark:text-red-400"
                                >Dangerous</span
                            >
                        {:else if jwtResult.isWeakAlg}
                            <span
                                class="rounded bg-amber-100 px-1.5 py-0.5 text-xs font-medium text-amber-800 dark:bg-amber-900/40 dark:text-amber-400"
                                >Weak</span
                            >
                        {/if}
                    </dd>
                </div>
                {#if typ}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Type<InfoTip key="jwt.tokenType" /></dt>
                        <dd class="font-mono text-sm text-neutral-900 dark:text-neutral-100">{typ}</dd>
                    </div>
                {/if}
                {#if kid}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Key ID<InfoTip key="jwt.keyId" /></dt>
                        <dd class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                            >{kid}</dd
                        >
                    </div>
                {/if}
                {#if iss}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Issuer<InfoTip key="jwt.issuer" /></dt>
                        <dd class="flex flex-wrap items-center gap-3">
                            <span class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100">{iss}</span>
                            {#if !discoveryResult && !discoveryLoading}
                                <button
                                    onclick={fetchDiscovery}
                                    class="shrink-0 rounded px-2 py-0.5 text-xs text-neutral-400 ring-1 ring-neutral-300 transition-colors hover:bg-neutral-100 hover:text-neutral-600 dark:ring-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300"
                                >Discover</button>
                            {:else if discoveryLoading}
                                <span class="shrink-0 text-xs text-neutral-400">Fetching…</span>
                            {:else if discoveryResult}
                                <span class="shrink-0 rounded bg-green-100 px-1.5 py-0.5 text-xs font-medium text-green-800 dark:bg-green-900/40 dark:text-green-400">Discovered</span>
                            {/if}
                        </dd>
                    </div>
                {/if}
                {#if sub}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Subject<InfoTip key="jwt.subject" /></dt>
                        <dd class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                            >{sub}</dd
                        >
                    </div>
                {/if}
                {#if audArr}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Audience<InfoTip key="jwt.audience" /></dt>
                        <dd class="flex flex-col gap-0.5">
                            {#each audArr as aud, audIdx (audIdx)}
                                <span
                                    class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                                    >{String(aud)}</span
                                >
                            {/each}
                        </dd>
                    </div>
                {/if}
                {#if jti}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">JWT ID<InfoTip key="jwt.jwtId" /></dt>
                        <dd class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                            >{jti}</dd
                        >
                    </div>
                {/if}
            </dl>
        </div>

        <!-- Timestamps -->
        {#if hasTimestamps}
            <div
                class="overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-900"
            >
                <div class="border-b border-neutral-200 px-4 py-2.5 dark:border-neutral-800">
                    <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500"
                        >Timestamps</span
                    >
                </div>
                <dl class="divide-y divide-neutral-100 dark:divide-neutral-800">
                    {#if jwtResult.timestamps.iat}
                        {@const ts = jwtResult.timestamps.iat}
                        <div class="flex flex-wrap items-baseline gap-x-4 gap-y-1 px-4 py-2.5">
                            <dt class="w-36 shrink-0 text-sm text-neutral-500">Issued At<InfoTip key="jwt.ts.issuedAt" /></dt>
                            <dd class="flex flex-wrap items-baseline gap-3">
                                <span
                                    class="font-mono text-sm text-neutral-900 dark:text-neutral-100"
                                    >{ts.date.toISOString()}</span
                                >
                                <span
                                    class="text-xs {ts.expired
                                        ? 'text-red-600 dark:text-red-400'
                                        : 'text-green-700 dark:text-green-400'}">{ts.label}</span
                                >
                            </dd>
                        </div>
                    {/if}
                    {#if jwtResult.timestamps.nbf}
                        {@const ts = jwtResult.timestamps.nbf}
                        <div class="flex flex-wrap items-baseline gap-x-4 gap-y-1 px-4 py-2.5">
                            <dt class="w-36 shrink-0 text-sm text-neutral-500">Not Before<InfoTip key="jwt.ts.notBefore" /></dt>
                            <dd class="flex flex-wrap items-baseline gap-3">
                                <span
                                    class="font-mono text-sm text-neutral-900 dark:text-neutral-100"
                                    >{ts.date.toISOString()}</span
                                >
                                <span
                                    class="text-xs {ts.expired
                                        ? 'text-red-600 dark:text-red-400'
                                        : 'text-green-700 dark:text-green-400'}">{ts.label}</span
                                >
                            </dd>
                        </div>
                    {/if}
                    {#if jwtResult.timestamps.exp}
                        {@const ts = jwtResult.timestamps.exp}
                        <div class="flex flex-wrap items-baseline gap-x-4 gap-y-1 px-4 py-2.5">
                            <dt class="w-36 shrink-0 text-sm text-neutral-500">Expires<InfoTip key="jwt.ts.expires" /></dt>
                            <dd class="flex flex-wrap items-baseline gap-3">
                                <span
                                    class="font-mono text-sm text-neutral-900 dark:text-neutral-100"
                                    >{ts.date.toISOString()}</span
                                >
                                <span
                                    class="text-xs {ts.expired
                                        ? 'text-red-600 dark:text-red-400'
                                        : 'text-green-700 dark:text-green-400'}">{ts.label}</span
                                >
                            </dd>
                        </div>
                    {/if}
                </dl>
            </div>
        {/if}

        <!-- Scopes -->
        {#if jwtResult.scopes && jwtResult.scopes.length > 0}
            <div
                class="overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-900"
            >
                <div class="border-b border-neutral-200 px-4 py-2.5 dark:border-neutral-800">
                    <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500"
                        >Scopes<InfoTip key="jwt.scopes" /></span
                    >
                </div>
                <div class="flex flex-wrap gap-2 p-4">
                    {#each jwtResult.scopes as scope (scope)}
                        <span
                            class="rounded bg-neutral-200 px-2 py-0.5 font-mono text-xs text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300"
                            >{scope}</span
                        >
                    {/each}
                </div>
            </div>
        {/if}

        <!-- Discovery error -->
        {#if discoveryError}
            <div
                class="rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-700 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-400"
            >
                <strong>OIDC Discovery:</strong>
                {discoveryError}
            </div>
        {/if}

        <!-- Discovery results -->
        {#if discoveryResult}
            {@const jwksUri = safeHref(typeof discoveryResult.jwks_uri === 'string' ? discoveryResult.jwks_uri : null)}
            {@const authEp = safeHref(typeof discoveryResult.authorization_endpoint === 'string' ? discoveryResult.authorization_endpoint : null)}
            {@const tokenEp = safeHref(typeof discoveryResult.token_endpoint === 'string' ? discoveryResult.token_endpoint : null)}
            {@const userinfoEp = safeHref(typeof discoveryResult.userinfo_endpoint === 'string' ? discoveryResult.userinfo_endpoint : null)}
            {@const supportedAlgs = Array.isArray(discoveryResult.id_token_signing_alg_values_supported) ? discoveryResult.id_token_signing_alg_values_supported as string[] : null}
            {@const acrValues = Array.isArray(discoveryResult.acr_values_supported) ? discoveryResult.acr_values_supported as string[] : null}
            <div
                class="overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-900"
            >
                <div class="border-b border-neutral-200 px-4 py-2.5 dark:border-neutral-800">
                    <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500">OIDC Discovery</span>
                </div>
                <dl class="divide-y divide-neutral-100 dark:divide-neutral-800">
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Issuer</dt>
                        <dd class="flex flex-wrap items-center gap-2">
                            <span class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100">{typeof discoveryResult.issuer === 'string' ? discoveryResult.issuer : '—'}</span>
                            {#if discoveryIssuerMatch === true}
                                <span class="shrink-0 rounded bg-green-100 px-1.5 py-0.5 text-xs font-medium text-green-800 dark:bg-green-900/40 dark:text-green-400">Matches token</span>
                            {:else if discoveryIssuerMatch === false}
                                <span class="shrink-0 rounded bg-red-100 px-1.5 py-0.5 text-xs font-medium text-red-800 dark:bg-red-900/40 dark:text-red-400">Mismatch</span>
                            {/if}
                        </dd>
                    </div>
                    {#if jwksUri}
                        <div class="flex gap-4 px-4 py-2.5">
                            <dt class="w-36 shrink-0 text-sm text-neutral-500">JWKS URI</dt>
                            <dd class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100">
                                <a href={jwksUri} target="_blank" rel="noopener noreferrer" class="underline decoration-neutral-300 hover:decoration-neutral-500 dark:decoration-neutral-600 dark:hover:decoration-neutral-400">{jwksUri}</a>
                            </dd>
                        </div>
                    {/if}
                    {#if authEp}
                        <div class="flex gap-4 px-4 py-2.5">
                            <dt class="w-36 shrink-0 text-sm text-neutral-500">Auth Endpoint</dt>
                            <dd class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100">
                                <a href={authEp} target="_blank" rel="noopener noreferrer" class="underline decoration-neutral-300 hover:decoration-neutral-500 dark:decoration-neutral-600 dark:hover:decoration-neutral-400">{authEp}</a>
                            </dd>
                        </div>
                    {/if}
                    {#if tokenEp}
                        <div class="flex gap-4 px-4 py-2.5">
                            <dt class="w-36 shrink-0 text-sm text-neutral-500">Token Endpoint</dt>
                            <dd class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100">
                                <a href={tokenEp} target="_blank" rel="noopener noreferrer" class="underline decoration-neutral-300 hover:decoration-neutral-500 dark:decoration-neutral-600 dark:hover:decoration-neutral-400">{tokenEp}</a>
                            </dd>
                        </div>
                    {/if}
                    {#if userinfoEp}
                        <div class="flex gap-4 px-4 py-2.5">
                            <dt class="w-36 shrink-0 text-sm text-neutral-500">UserInfo</dt>
                            <dd class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100">
                                <a href={userinfoEp} target="_blank" rel="noopener noreferrer" class="underline decoration-neutral-300 hover:decoration-neutral-500 dark:decoration-neutral-600 dark:hover:decoration-neutral-400">{userinfoEp}</a>
                            </dd>
                        </div>
                    {/if}
                    {#if supportedAlgs}
                        <div class="flex gap-4 px-4 py-2.5">
                            <dt class="w-36 shrink-0 text-sm text-neutral-500">ID Token Algs</dt>
                            <dd class="flex flex-wrap gap-1.5">
                                {#each supportedAlgs as a (a)}
                                    <span class="rounded px-1.5 py-0.5 font-mono text-xs {a === alg ? (discoveryAlgOk ? 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-400' : 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-400') : 'bg-neutral-200 text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300'}">{a}</span>
                                {/each}
                                {#if discoveryAlgOk === false}
                                    <span class="rounded bg-red-100 px-1.5 py-0.5 text-xs font-medium text-red-800 dark:bg-red-900/40 dark:text-red-400">Token alg not supported</span>
                                {/if}
                            </dd>
                        </div>
                    {/if}
                    {#if acrValues && acrValues.length > 0}
                        <div class="flex gap-4 px-4 py-2.5">
                            <dt class="w-36 shrink-0 text-sm text-neutral-500">ACR Values</dt>
                            <dd class="flex flex-wrap gap-1.5">
                                {#each acrValues as acr (acr)}
                                    <span class="rounded bg-neutral-200 px-1.5 py-0.5 font-mono text-xs text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300">{acr}</span>
                                {/each}
                            </dd>
                        </div>
                    {/if}
                </dl>
            </div>
        {/if}

        <!-- Header + Payload JSON -->
        <div class="grid gap-4 sm:grid-cols-2">
            <div>
                <div class="mb-2">
                    <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500"
                        >Header</span
                    >
                </div>
                <pre
                    class="max-h-64 overflow-auto rounded-lg border border-neutral-200 bg-neutral-50 p-4 font-mono text-xs leading-relaxed text-neutral-800 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-300">{JSON.stringify(
                        jwtResult.header,
                        null,
                        2
                    )}</pre>
            </div>
            <div>
                <div class="mb-2 flex items-center justify-between">
                    <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500"
                        >Payload</span
                    >
                    <button
                        onclick={copyJwt}
                        class="rounded px-2.5 py-1 text-xs text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300"
                    >
                        {jwtCopied ? 'Copied!' : 'Copy token'}
                    </button>
                </div>
                <pre
                    class="max-h-64 overflow-auto rounded-lg border border-neutral-200 bg-neutral-50 p-4 font-mono text-xs leading-relaxed text-neutral-800 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-300">{JSON.stringify(
                        jwtResult.payload,
                        null,
                        2
                    )}</pre>
            </div>
        </div>
    {/if}

    {#if decodeError}
        <div
            class="rounded-lg border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950/30 dark:text-red-400"
        >
            {decodeError}
        </div>
    {/if}

    <!-- Generic fallback results -->
    {#each genericResults as gr, i (i)}
        <div class="space-y-3">
            <div class="flex items-center gap-3">
                <span
                    class="rounded-md bg-amber-100 px-2.5 py-1 text-xs font-medium text-amber-800 dark:bg-amber-900/40 dark:text-amber-400"
                >
                    Not SAML
                </span>
                {#if genericResults.length > 1}
                    <span class="text-xs text-neutral-400">{i + 1} of {genericResults.length}</span>
                {/if}
                <span class="text-sm text-neutral-500">
                    Decoded as <span class="font-medium text-neutral-700 dark:text-neutral-300"
                        >{ENCODING_LABELS[gr.encoding]}</span
                    >
                    {#if gr.contentType !== 'text'}
                        — looks like <span
                            class="font-medium text-neutral-700 dark:text-neutral-300"
                            >{gr.contentType.toUpperCase()}</span
                        >
                    {/if}
                </span>
            </div>
            <div>
                <div class="mb-2 flex items-center justify-between">
                    <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500"
                        >Decoded Content</span
                    >
                    <button
                        onclick={() => copyGenericContent(i)}
                        class="rounded px-2.5 py-1 text-xs text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300"
                    >
                        {genericCopiedIdx === i ? 'Copied!' : 'Copy'}
                    </button>
                </div>
                <pre
                    class="max-h-96 overflow-auto rounded-lg border border-neutral-200 bg-neutral-50 p-4 font-mono text-xs leading-relaxed text-neutral-800 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-300">{gr.content}</pre>
            </div>
        </div>
    {/each}

    <!-- SAML results -->
    {#each results as result, i (i)}
        {@const s = result.summary}

        {#if results.length > 1}
            <div
                class="flex items-center gap-3 border-t border-neutral-200 pt-6 dark:border-neutral-800"
            >
                <span class="text-xs font-semibold uppercase tracking-wider text-neutral-400"
                    >Message {i + 1} of {results.length}</span
                >
                <span
                    class="rounded bg-neutral-200 px-1.5 py-0.5 font-mono text-xs text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300"
                >
                    {s.messageType}
                </span>
            </div>
        {/if}

        <!-- Summary -->
        <div
            class="overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-900"
        >
            <div class="border-b border-neutral-200 px-4 py-2.5 dark:border-neutral-800">
                <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500"
                    >Summary</span
                >
            </div>
            <dl class="divide-y divide-neutral-100 dark:divide-neutral-800">
                <div class="flex gap-4 px-4 py-2.5">
                    <dt class="w-36 shrink-0 text-sm text-neutral-500">Binding<InfoTip key="saml.binding" /></dt>
                    <dd class="text-sm">
                        <span
                            class="rounded bg-neutral-200 px-1.5 py-0.5 font-mono text-xs text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300"
                        >
                            {s.binding === 'redirect' ? 'HTTP-Redirect' : 'HTTP-POST'}
                        </span>
                    </dd>
                </div>
                <div class="flex gap-4 px-4 py-2.5">
                    <dt class="w-36 shrink-0 text-sm text-neutral-500">Message<InfoTip key="saml.messageType" /></dt>
                    <dd class="text-sm">
                        <span
                            class="rounded bg-neutral-200 px-1.5 py-0.5 font-mono text-xs text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300"
                        >
                            {s.messageType}
                        </span>
                    </dd>
                </div>
                {#if s.status}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Status<InfoTip key="saml.status" /></dt>
                        <dd class="flex flex-col gap-1">
                            <div class="flex flex-wrap items-baseline gap-2">
                                <span
                                    class="rounded px-1.5 py-0.5 text-xs font-medium {shortCode(
                                        s.status.code
                                    ) === 'Success'
                                        ? 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-400'
                                        : 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-400'}"
                                >
                                    {shortCode(s.status.code)}
                                </span>
                                {#if s.status.subCode}
                                    {@const subUrl = STATUS_SPEC_URLS[s.status.subCode]}
                                    {#if subUrl}
                                        <a
                                            href={subUrl}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            class="font-mono text-xs text-neutral-500 underline decoration-dotted hover:text-neutral-300"
                                            >{shortCode(s.status.subCode)}</a
                                        >
                                    {:else}
                                        <span class="font-mono text-xs text-neutral-500"
                                            >{shortCode(s.status.subCode)}</span
                                        >
                                    {/if}
                                {/if}
                                {#if s.status.message}
                                    <span class="text-xs text-neutral-500 italic"
                                        >{s.status.message}</span
                                    >
                                {/if}
                            </div>
                            {#if shortCode(s.status.code) !== 'Success'}
                                {@const desc = STATUS_DESCRIPTIONS[s.status.subCode ?? s.status.code]}
                                {#if desc}
                                    <p class="text-xs text-neutral-400 dark:text-neutral-500">{desc}</p>
                                {/if}
                            {/if}
                        </dd>
                    </div>
                {/if}
                {#if s.issuer}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Issuer<InfoTip key="saml.issuer" /></dt>
                        <dd
                            class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                        >
                            {s.issuer}
                        </dd>
                    </div>
                {/if}
                {#if s.destination}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Destination<InfoTip key="saml.destination" /></dt>
                        <dd
                            class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                        >
                            {s.destination}
                        </dd>
                    </div>
                {/if}
                {#if s.acsUrl}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">ACS URL<InfoTip key="saml.acsUrl" /></dt>
                        <dd
                            class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                        >
                            {s.acsUrl}
                        </dd>
                    </div>
                {/if}
                {#if s.requestedAuthnContext?.classRefs.length}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Requested AuthnContext<InfoTip key="saml.requestedAuthnContext" /></dt>
                        <dd class="flex flex-col gap-1">
                            <div class="flex flex-wrap items-baseline gap-2">
                                {#each s.requestedAuthnContext.classRefs as ref (ref)}
                                    <span class="rounded bg-neutral-200 px-1.5 py-0.5 font-mono text-xs text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300">
                                        {AUTHN_CONTEXT_LABELS[ref] ?? ref}
                                    </span>
                                {/each}
                                <span class="text-xs text-neutral-500">{s.requestedAuthnContext.comparison}</span>
                            </div>
                            {#each s.requestedAuthnContext.classRefs as ref (ref)}
                                {#if ref in AUTHN_CONTEXT_LABELS}
                                    {@const specUrl = AUTHN_CONTEXT_SPEC_URLS[ref] ?? safeHref(ref)}
                                    {#if specUrl}
                                        <a href={specUrl} target="_blank" rel="noopener noreferrer" class="font-mono text-xs text-neutral-400 break-all transition-colors hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300">{ref}</a>
                                    {:else}
                                        <span class="font-mono text-xs text-neutral-400 dark:text-neutral-500 break-all">{ref}</span>
                                    {/if}
                                {/if}
                            {/each}
                        </dd>
                    </div>
                {/if}
                {#if s.nameId}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">NameID<InfoTip key="saml.nameId" /></dt>
                        <dd class="flex flex-wrap items-baseline gap-2">
                            <span class="font-mono text-sm text-neutral-900 dark:text-neutral-100">
                                {s.nameId.value}
                            </span>
                            <span class="text-xs text-neutral-500"
                                >{shortFormat(s.nameId.format)}</span
                            >
                        </dd>
                    </div>
                {/if}
                {#if s.authnContext?.classRef}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">AuthnContext<InfoTip key="saml.authnContext" /></dt>
                        <dd class="flex flex-col gap-1">
                            <div class="flex flex-wrap items-baseline gap-2">
                                <span class="rounded bg-neutral-200 px-1.5 py-0.5 font-mono text-xs text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300">
                                    {AUTHN_CONTEXT_LABELS[s.authnContext.classRef] ?? s.authnContext.classRef}
                                </span>
                                {#if s.authnContext.declRef}
                                    <span class="font-mono text-xs text-neutral-500">{s.authnContext.declRef}</span>
                                {/if}
                            </div>
                            {#if s.authnContext.classRef in AUTHN_CONTEXT_LABELS}
                                {@const specUrl = AUTHN_CONTEXT_SPEC_URLS[s.authnContext.classRef] ?? safeHref(s.authnContext.classRef)}
                                {#if specUrl}
                                    <a href={specUrl} target="_blank" rel="noopener noreferrer" class="font-mono text-xs text-neutral-400 break-all transition-colors hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300">{s.authnContext.classRef}</a>
                                {:else}
                                    <span class="font-mono text-xs text-neutral-400 dark:text-neutral-500 break-all">{s.authnContext.classRef}</span>
                                {/if}
                            {/if}
                        </dd>
                    </div>
                {/if}
                {#if s.inResponseTo}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">InResponseTo<InfoTip key="saml.inResponseTo" /></dt>
                        <dd
                            class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                        >
                            {s.inResponseTo}
                        </dd>
                    </div>
                {/if}
                {#if s.relayState}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">RelayState<InfoTip key="saml.relayState" /></dt>
                        <dd
                            class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                        >
                            {s.relayState}
                        </dd>
                    </div>
                {/if}
                {#if s.encrypted.assertion || s.encrypted.nameId}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Encrypted<InfoTip key="saml.encrypted" /></dt>
                        <dd class="flex flex-wrap gap-2">
                            {#if s.encrypted.assertion}
                                <span
                                    class="rounded bg-amber-100 px-1.5 py-0.5 text-xs font-medium text-amber-800 dark:bg-amber-900/40 dark:text-amber-400"
                                >
                                    Assertion
                                </span>
                            {/if}
                            {#if s.encrypted.nameId}
                                <span
                                    class="rounded bg-amber-100 px-1.5 py-0.5 text-xs font-medium text-amber-800 dark:bg-amber-900/40 dark:text-amber-400"
                                >
                                    NameID
                                </span>
                            {/if}
                        </dd>
                    </div>
                {/if}
                {#if s.signingCertificate}
                    {@const certKey = s.signingCertificate.slice(0, 20)}
                    {@const c = certInfos[certKey]}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Signing cert<InfoTip key="saml.signingCert" /></dt>
                        <dd class="space-y-1.5">
                            {#if c === false}
                                <span class="text-sm text-neutral-500"
                                    >present (could not decode)</span
                                >
                            {:else if c}
                                <div class="flex flex-wrap gap-2">
                                    <span
                                        class="rounded px-1.5 py-0.5 font-mono text-xs {c.isValid
                                            ? 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-400'
                                            : 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-400'}"
                                    >
                                        {c.isValid ? 'Valid' : 'Expired'}
                                    </span>
                                    <span
                                        class="rounded bg-neutral-200 px-1.5 py-0.5 font-mono text-xs text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300"
                                    >
                                        {c.keyAlgorithm}
                                    </span>
                                </div>
                                <div
                                    class="font-mono text-xs text-neutral-700 dark:text-neutral-300"
                                >
                                    {c.subject}
                                </div>
                                <div class="font-mono text-xs text-neutral-500">
                                    Issuer: {c.issuer}
                                </div>
                                <div class="text-xs text-neutral-500">
                                    {c.validFrom.toISOString().slice(0, 10)} →
                                    {c.validTo.toISOString().slice(0, 10)}
                                    <span
                                        class="ml-1 {isExpired(c.validTo)
                                            ? 'text-red-600 dark:text-red-400'
                                            : 'text-green-700 dark:text-green-400'}"
                                    >
                                        ({relativeLabel(c.validTo)})
                                    </span>
                                </div>
                            {/if}
                        </dd>
                    </div>
                {/if}
            </dl>
        </div>

        <!-- Timestamps -->
        {#if s.timestamps.length > 0}
            <div
                class="overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-900"
            >
                <div class="border-b border-neutral-200 px-4 py-2.5 dark:border-neutral-800">
                    <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500"
                        >Timestamps</span
                    >
                </div>
                <dl class="divide-y divide-neutral-100 dark:divide-neutral-800">
                    {#each s.timestamps as ts (ts.label)}
                        {@const expired = isExpired(ts.date)}
                        <div class="flex flex-wrap items-baseline gap-x-4 gap-y-1 px-4 py-2.5">
                            <dt class="w-36 shrink-0 text-sm text-neutral-500">{ts.label}<InfoTip key={SAML_TS_KEY[ts.label]} /></dt>
                            <dd class="flex flex-wrap items-baseline gap-3">
                                <span
                                    class="font-mono text-sm text-neutral-900 dark:text-neutral-100"
                                    >{ts.raw}</span
                                >
                                <span
                                    class="text-xs {expired
                                        ? 'text-red-600 dark:text-red-400'
                                        : 'text-green-700 dark:text-green-400'}"
                                >
                                    {relativeLabel(ts.date)}
                                </span>
                            </dd>
                        </div>
                    {/each}
                </dl>
            </div>
        {/if}

        <!-- Attributes -->
        {#if s.attributes.length > 0}
            <div
                class="overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-900"
            >
                <div class="border-b border-neutral-200 px-4 py-2.5 dark:border-neutral-800">
                    <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500">
                        Released Attributes<InfoTip key="saml.attributes" />
                        <span class="ml-1 font-normal normal-case text-neutral-400"
                            >({s.attributes.length})</span
                        >
                    </span>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-sm">
                        <thead>
                            <tr class="border-b border-neutral-200 dark:border-neutral-800">
                                <th class="px-4 py-2 text-left text-xs font-medium text-neutral-500"
                                    >Name</th
                                >
                                <th class="px-4 py-2 text-left text-xs font-medium text-neutral-500"
                                    >Friendly Name</th
                                >
                                <th class="px-4 py-2 text-left text-xs font-medium text-neutral-500"
                                    >Values</th
                                >
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-neutral-100 dark:divide-neutral-800">
                            {#each s.attributes as attribute (attribute.name)}
                                {@const attrInfo = getAttributeInfo(attribute.name)}
                                {@const scopedStatus = eppnScopedStatus(attribute.name, attribute.values)}
                                <tr>
                                    <td class="px-4 py-2 text-xs text-neutral-700 dark:text-neutral-300">
                                        <div class="font-mono whitespace-nowrap">{attribute.name}</div>
                                        {#if (attrInfo?.categories.length ?? 0) > 0 || scopedStatus !== null}
                                            <div class="mt-1 flex flex-wrap gap-1">
                                                {#if attrInfo?.categories.includes('rs')}
                                                    <span
                                                        class="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-400"
                                                        title="REFEDS Research & Scholarship attribute bundle — applies to IdPs and SPs that have registered the R&S entity category in their metadata"
                                                    >R&amp;S</span>
                                                {/if}
                                                {#if scopedStatus === 'scoped'}
                                                    <span
                                                        class="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium bg-violet-100 text-violet-700 dark:bg-violet-900/40 dark:text-violet-400"
                                                        title="Properly scoped ePPN — satisfies REFEDS RAF eppn-unique-no-reassign requirements"
                                                    >eppn-scoped</span>
                                                {:else if scopedStatus === 'unscoped'}
                                                    <span
                                                        class="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-400"
                                                        title="Unscoped ePPN — eduPersonPrincipalName should contain @scope per InCommon requirements"
                                                    >⚠ unscoped</span>
                                                {/if}
                                            </div>
                                        {/if}
                                    </td>
                                    <td class="px-4 py-2 text-xs text-neutral-500">
                                        {attribute.friendlyName ?? attrInfo?.friendlyName ?? ''}
                                    </td>
                                    <td
                                        class="px-4 py-2 font-mono text-xs text-neutral-900 dark:text-neutral-100"
                                    >
                                        {attribute.values.join(', ')}
                                    </td>
                                </tr>
                            {/each}
                        </tbody>
                    </table>
                </div>
            </div>
        {/if}

        <!-- XML -->
        <div>
            <div class="mb-2 flex items-center justify-between">
                <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500"
                    >XML</span
                >
                <button
                    onclick={() => copySamlXml(i)}
                    class="rounded px-2.5 py-1 text-xs text-neutral-500 transition-colors hover:bg-neutral-100 hover:text-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300"
                >
                    {samlCopiedIdx === i ? 'Copied!' : 'Copy'}
                </button>
            </div>
            <!-- eslint-disable svelte/no-at-html-tags -->
            <pre
                class="overflow-x-auto rounded-lg border border-neutral-200 bg-neutral-50 p-4 font-mono text-xs leading-relaxed text-neutral-800 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-300"
                onmouseover={handleXmlMouseover}
                onmouseleave={handleXmlMouseleave}
            >{@html highlightXml(result.xml)}</pre>
            <!-- eslint-enable svelte/no-at-html-tags -->
        </div>
    {/each}
</div>

{#if xmlTip}
    <div
        class="xml-tip"
        style="left: {Math.min(xmlTip.x, window.innerWidth - 320)}px; top: {xmlTip.y}px"
        role="tooltip"
    >
        <span class="xml-tip-el">&lt;{xmlTip.el}&gt;</span>
        {xmlTip.text}
    </div>
{/if}

<style>
    :global(.xml-punct) { color: #6b7280; }
    :global(.xml-el) { color: #60a5fa; }
    :global(.xml-el-tip) { cursor: help; text-decoration: underline dotted; text-decoration-thickness: 1px; }
    :global(.xml-attr-name) { color: #34d399; }
    :global(.xml-attr-val) { color: #fb923c; }
    :global(.xml-comment) { color: #6b7280; font-style: italic; }
    :global(.xml-prolog) { color: #9ca3af; font-style: italic; }

    :global(html:not(.dark) .xml-punct) { color: #4b5563; }
    :global(html:not(.dark) .xml-el) { color: #2563eb; }
    :global(html:not(.dark) .xml-attr-name) { color: #059669; }
    :global(html:not(.dark) .xml-attr-val) { color: #ea580c; }
    :global(html:not(.dark) .xml-comment) { color: #6b7280; }
    :global(html:not(.dark) .xml-prolog) { color: #9ca3af; }

    .xml-tip {
        position: fixed;
        z-index: 50;
        max-width: 18rem;
        border-radius: 0.375rem;
        background: #1f2937;
        padding: 0.5rem 0.75rem;
        font-size: 0.75rem;
        line-height: 1.4;
        color: #e5e7eb;
        box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.4);
        pointer-events: none;
    }

    .xml-tip-el {
        display: block;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 0.7rem;
        color: #93c5fd;
        margin-bottom: 0.25rem;
    }
</style>
