<script lang="ts">
    import {
        applyEdits,
        COMPARISONS,
        encodeRequest,
        hasEmbeddedSignature,
        nowInstant,
        readFields,
        redirectUrl,
        validateFields,
        type AuthnRequestFields,
        type Comparison
    } from '#lib/authn-edit.ts';
    import {
        AUTHN_CONTEXT_LABELS,
        prettyPrintXml,
        type BindingType,
        type SamlSource
    } from '#lib/saml.ts';
    import InfoTip from '#lib/InfoTip.svelte';

    let { source, binding }: { source: SamlSource; binding: BindingType } = $props();
    // unique per instance, so labels still match when a paste holds several requests
    const uid = $props.id();

    const MFA = 'https://refeds.org/profile/mfa';
    const PPT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

    let open = $state(false);
    let issueInstant = $state('');
    let acsUrl = $state('');
    let acsIndex = $state('');
    let refsText = $state('');
    let comparison = $state<Comparison>('exact');
    let showXml = $state(false);
    let copied = $state<'value' | 'url' | null>(null);

    function load() {
        const f = readFields(source.xml);
        issueInstant = f.issueInstant;
        acsUrl = f.acsUrl;
        acsIndex = f.acsIndex;
        refsText = f.classRefs.join('\n');
        comparison = f.comparison;
        copied = null;
    }

    // a different message in the same slot starts from its own values
    $effect(() => {
        void source.xml;
        load();
    });

    const fields = $derived<AuthnRequestFields>({
        issueInstant: issueInstant.trim(),
        acsUrl: acsUrl.trim(),
        acsIndex: acsIndex.trim(),
        classRefs: refsText
            .split('\n')
            .map((r) => r.trim())
            .filter(Boolean),
        comparison
    });
    const problems = $derived(validateFields(fields));
    const edited = $derived(problems.length === 0 ? applyEdits(source.xml, fields) : null);
    const value = $derived(edited ? encodeRequest(edited, binding) : null);
    const url = $derived(
        value && binding === 'redirect' && source.endpoint
            ? redirectUrl(source.endpoint, value, source.relayState)
            : null
    );
    const embeddedSig = $derived(hasEmbeddedSignature(source.xml));

    function addRef(ref: string) {
        const refs = refsText
            .split('\n')
            .map((r) => r.trim())
            .filter(Boolean);
        if (!refs.includes(ref)) refsText = [...refs, ref].join('\n');
    }

    async function copy(which: 'value' | 'url', text: string) {
        try {
            await navigator.clipboard.writeText(text);
            copied = which;
            setTimeout(() => {
                if (copied === which) copied = null;
            }, 2000);
        } catch {
            // clipboard refused; the text is selectable in the box
        }
    }

    const btn =
        'rounded px-2 py-0.5 text-xs text-neutral-400 ring-1 ring-neutral-300 transition-colors hover:bg-neutral-100 hover:text-neutral-600 dark:ring-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300';
    const input =
        'w-full rounded border border-neutral-300 bg-white px-2 py-1 font-mono text-xs text-neutral-800 dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-200';
    const label = 'w-36 shrink-0 pt-1 text-sm text-neutral-500';
</script>

<div
    class="overflow-hidden rounded-lg border border-neutral-200 bg-neutral-50 dark:border-neutral-800 dark:bg-neutral-900"
>
    <div
        class="flex items-center justify-between border-b border-neutral-200 px-4 py-2.5 dark:border-neutral-800"
    >
        <span class="text-xs font-semibold uppercase tracking-wider text-neutral-500"
            >Edit Request<InfoTip key="saml.editRequest" /></span
        >
        <button type="button" class={btn} aria-expanded={open} onclick={() => (open = !open)}
            >{open ? 'Close' : 'Edit and re-encode'}</button
        >
    </div>

    {#if open}
        <div class="space-y-3 px-4 py-3">
            <div class="flex gap-4">
                <label class={label} for={`${uid}-instant`}>IssueInstant</label>
                <div class="flex min-w-0 flex-1 items-center gap-2">
                    <input
                        id={`${uid}-instant`}
                        class={input}
                        bind:value={issueInstant}
                        spellcheck="false"
                    />
                    <button type="button" class={btn} onclick={() => (issueInstant = nowInstant())}
                        >Now</button
                    >
                </div>
            </div>
            <div class="flex gap-4">
                <label class={label} for={`${uid}-acs`}>ACS URL</label>
                <input
                    id={`${uid}-acs`}
                    class={input}
                    bind:value={acsUrl}
                    spellcheck="false"
                    placeholder="https://sp.example.org/Shibboleth.sso/SAML2/POST"
                />
            </div>
            <div class="flex gap-4">
                <label class={label} for={`${uid}-index`}>ACS index</label>
                <input
                    id={`${uid}-index`}
                    class="{input} max-w-24"
                    bind:value={acsIndex}
                    inputmode="numeric"
                    placeholder="—"
                />
            </div>
            <div class="flex gap-4">
                <label class={label} for={`${uid}-refs`}>AuthnContext</label>
                <div class="min-w-0 flex-1 space-y-1.5">
                    <textarea
                        id={`${uid}-refs`}
                        class={input}
                        rows="2"
                        bind:value={refsText}
                        spellcheck="false"
                        placeholder="One class reference per line; empty removes RequestedAuthnContext"
                    ></textarea>
                    <div class="flex flex-wrap items-center gap-2">
                        <button type="button" class={btn} onclick={() => addRef(MFA)}
                            >+ {AUTHN_CONTEXT_LABELS[MFA] ?? 'REFEDS MFA'}</button
                        >
                        <button type="button" class={btn} onclick={() => addRef(PPT)}
                            >+ {AUTHN_CONTEXT_LABELS[PPT] ?? 'PasswordProtectedTransport'}</button
                        >
                        <label class="ml-2 text-xs text-neutral-500" for={`${uid}-cmp`}
                            >Comparison</label
                        >
                        <select
                            id={`${uid}-cmp`}
                            class="rounded border border-neutral-300 bg-white px-1 py-0.5 text-xs dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-200"
                            bind:value={comparison}
                        >
                            {#each COMPARISONS as c (c)}
                                <option value={c}>{c}</option>
                            {/each}
                        </select>
                    </div>
                </div>
            </div>

            {#if problems.length > 0}
                <ul class="space-y-0.5 text-xs text-red-600 dark:text-red-400">
                    {#each problems as p (p)}<li>{p}</li>{/each}
                </ul>
            {/if}

            {#if source.redirectSigned || embeddedSig}
                <div
                    class="rounded border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-400"
                >
                    {#if source.redirectSigned}
                        The original redirect was signed (SigAlg and Signature). The re-encoded URL
                        carries no signature, because the request cannot be re-signed in the
                        browser.
                    {:else}
                        The request carries an embedded ds:Signature, which no longer matches once
                        the request is edited.
                    {/if}
                    The IdP has to accept unsigned requests from this SP for the edited request to work.
                </div>
            {/if}

            {#if value}
                <div class="space-y-1">
                    <div class="flex items-center justify-between">
                        <span class="text-xs text-neutral-500"
                            >SAMLRequest ({binding === 'redirect'
                                ? 'HTTP-Redirect: DEFLATE + base64'
                                : 'HTTP-POST: base64'})</span
                        >
                        <button type="button" class={btn} onclick={() => copy('value', value)}
                            >{copied === 'value' ? 'Copied!' : 'Copy'}</button
                        >
                    </div>
                    <pre
                        class="max-h-24 overflow-auto whitespace-pre-wrap break-all rounded bg-neutral-100 p-2 font-mono text-[11px] text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300">{value}</pre>
                </div>
                {#if url}
                    <div class="space-y-1">
                        <div class="flex items-center justify-between">
                            <span class="text-xs text-neutral-500"
                                >Redirect URL{source.relayState ? ' (RelayState kept)' : ''}</span
                            >
                            <div class="flex gap-2">
                                <button type="button" class={btn} onclick={() => copy('url', url)}
                                    >{copied === 'url' ? 'Copied!' : 'Copy'}</button
                                >
                                <a class={btn} href={url} target="_blank" rel="noopener noreferrer"
                                    >Open</a
                                >
                            </div>
                        </div>
                        <pre
                            class="max-h-24 overflow-auto whitespace-pre-wrap break-all rounded bg-neutral-100 p-2 font-mono text-[11px] text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300">{url}</pre>
                    </div>
                {:else if binding === 'redirect'}
                    <div class="text-xs text-neutral-500">
                        Paste the full IdP URL, not just the parameter, to get a ready-to-use
                        redirect URL.
                    </div>
                {/if}
                <div class="flex items-center gap-2">
                    <button type="button" class={btn} onclick={() => (showXml = !showXml)}
                        >{showXml ? 'Hide edited XML' : 'Show edited XML'}</button
                    >
                    <button type="button" class={btn} onclick={load}>Reset</button>
                </div>
                {#if showXml && edited}
                    <pre
                        class="max-h-80 overflow-auto rounded bg-neutral-100 p-2 font-mono text-[11px] text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300">{prettyPrintXml(
                            edited
                        )}</pre>
                {/if}
            {/if}
        </div>
    {/if}
</div>
