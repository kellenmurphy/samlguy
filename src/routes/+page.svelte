<script lang="ts">
    import { decodeSaml, decodeAllSaml, type SamlDecodeResult } from '$lib/saml';
    import { decodeAllGeneric, type GenericDecodeResult } from '$lib/generic';
    import { relativeLabel, isExpired } from '$lib/time';
    import type { CertInfo } from '$lib/cert';

    type InputType = 'saml' | 'jwt' | null;

    let input = $state('');
    let results = $state<SamlDecodeResult[]>([]);
    let genericResults = $state<GenericDecodeResult[]>([]);
    let decodeError = $state<string | null>(null);
    // keyed by first 20 chars of cert base64; false = decode attempted but failed
    let certInfos = $state<Record<string, CertInfo | false>>({});
    let samlCopiedIdx = $state(-1);
    let genericCopiedIdx = $state(-1);

    function detect(value: string): InputType {
        const t = value.trim();
        if (!t) return null;
        if (/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$/.test(t)) return 'jwt';
        if (/^Authorization:\s*Bearer\s+/i.test(t)) return 'jwt';
        return 'saml';
    }

    const detected = $derived(detect(input));

    $effect(() => {
        const value = input.trim();

        if (!value || detected === 'jwt') {
            results = [];
            genericResults = [];
            decodeError = null;
            return;
        }

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
            let singleError: string | null = null;
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

    const ENCODING_LABELS: Record<string, string> = {
        'base64+deflate': 'base64 + DEFLATE',
        base64: 'base64',
        text: 'plain text'
    };
</script>

<div class="space-y-8">
    <div>
        <h1 class="text-2xl font-bold">Identity Decoder</h1>
        <p class="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
            Paste a SAML assertion, JWT, query string, URL, or HTTP log line. We'll figure it out.
        </p>
    </div>

    <textarea
        bind:value={input}
        placeholder="Paste anything — SAMLRequest, SAMLResponse, JWT, Authorization header, query string, full URL..."
        class="h-48 w-full resize-y rounded-lg border border-neutral-300 bg-neutral-50 px-4 py-3 font-mono text-sm text-neutral-900 placeholder-neutral-400 focus:border-neutral-500 focus:outline-none dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100 dark:placeholder-neutral-600"
    ></textarea>

    {#if detected === 'jwt' && results.length === 0}
        <div class="flex items-center gap-3">
            <span
                class="rounded-md bg-neutral-200 px-2.5 py-1 text-xs font-medium uppercase tracking-wider text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300"
            >
                JWT
            </span>
            <span class="text-sm text-neutral-500 italic">JWT decode coming soon</span>
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
    {#each genericResults as gr, i}
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
    {#each results as result, i}
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
                    <dt class="w-36 shrink-0 text-sm text-neutral-500">Binding</dt>
                    <dd class="text-sm">
                        <span
                            class="rounded bg-neutral-200 px-1.5 py-0.5 font-mono text-xs text-neutral-700 dark:bg-neutral-700 dark:text-neutral-300"
                        >
                            {s.binding === 'redirect' ? 'HTTP-Redirect' : 'HTTP-POST'}
                        </span>
                    </dd>
                </div>
                <div class="flex gap-4 px-4 py-2.5">
                    <dt class="w-36 shrink-0 text-sm text-neutral-500">Message</dt>
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
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Status</dt>
                        <dd class="flex flex-wrap items-baseline gap-2">
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
                                <span class="font-mono text-xs text-neutral-500"
                                    >{shortCode(s.status.subCode)}</span
                                >
                            {/if}
                            {#if s.status.message}
                                <span class="text-xs text-neutral-500 italic"
                                    >{s.status.message}</span
                                >
                            {/if}
                        </dd>
                    </div>
                {/if}
                {#if s.issuer}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Issuer</dt>
                        <dd
                            class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                        >
                            {s.issuer}
                        </dd>
                    </div>
                {/if}
                {#if s.destination}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Destination</dt>
                        <dd
                            class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                        >
                            {s.destination}
                        </dd>
                    </div>
                {/if}
                {#if s.acsUrl}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">ACS URL</dt>
                        <dd
                            class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                        >
                            {s.acsUrl}
                        </dd>
                    </div>
                {/if}
                {#if s.nameId}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">NameID</dt>
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
                {#if s.inResponseTo}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">InResponseTo</dt>
                        <dd
                            class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                        >
                            {s.inResponseTo}
                        </dd>
                    </div>
                {/if}
                {#if s.relayState}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">RelayState</dt>
                        <dd
                            class="break-all font-mono text-sm text-neutral-900 dark:text-neutral-100"
                        >
                            {s.relayState}
                        </dd>
                    </div>
                {/if}
                {#if s.encrypted.assertion || s.encrypted.nameId}
                    <div class="flex gap-4 px-4 py-2.5">
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Encrypted</dt>
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
                        <dt class="w-36 shrink-0 text-sm text-neutral-500">Signing cert</dt>
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
                    {#each s.timestamps as ts}
                        {@const expired = isExpired(ts.date)}
                        <div class="flex flex-wrap items-baseline gap-x-4 gap-y-1 px-4 py-2.5">
                            <dt class="w-36 shrink-0 text-sm text-neutral-500">{ts.label}</dt>
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
                        Released Attributes
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
                            {#each s.attributes as attribute}
                                <tr>
                                    <td
                                        class="max-w-xs break-all px-4 py-2 font-mono text-xs text-neutral-700 dark:text-neutral-300"
                                    >
                                        {attribute.name}
                                    </td>
                                    <td class="px-4 py-2 text-xs text-neutral-500">
                                        {attribute.friendlyName ?? ''}
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
            <pre
                class="max-h-96 overflow-auto rounded-lg border border-neutral-200 bg-neutral-50 p-4 font-mono text-xs leading-relaxed text-neutral-800 dark:border-neutral-800 dark:bg-neutral-900 dark:text-neutral-300">{result.xml}</pre>
        </div>
    {/each}
</div>
