<svelte:head>
    <title>Privacy Policy — samlguy.com</title>
    <meta name="description" content="Privacy policy for samlguy.com." />
</svelte:head>

<div class="prose prose-neutral max-w-2xl dark:prose-invert">
    <h1 class="text-2xl font-bold">Privacy Policy</h1>
    <p class="mt-1 text-sm text-neutral-500">Effective: May 2025</p>

    <div
        class="mt-6 flex items-start gap-3 rounded-lg border border-green-200 bg-green-50 px-4 py-3 dark:border-green-900/60 dark:bg-green-950/30"
    >
        <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
            class="mt-0.5 h-4 w-4 shrink-0 text-green-700 dark:text-green-400"
            aria-hidden="true"
        >
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
        <p class="text-sm font-medium text-green-800 dark:text-green-400">
            Everything is processed in your browser. Nothing you paste — SAML assertions, JWTs,
            certificates, or any other identity data — is ever transmitted to or stored on any server.
        </p>
    </div>

    <div class="mt-8 space-y-6 text-sm leading-relaxed text-neutral-700 dark:text-neutral-300">
        <section class="space-y-2">
            <h2 class="text-base font-semibold text-neutral-900 dark:text-neutral-100">
                What this tool does
            </h2>
            <p>
                samlguy.com hosts a client-side identity decoder. SAML assertions, JWTs, and any other
                content you paste are decoded entirely within your browser. Nothing you paste is
                transmitted to or stored on any server.
            </p>
        </section>

        <section class="space-y-2">
            <h2 class="text-base font-semibold text-neutral-900 dark:text-neutral-100">
                Data we do not collect
            </h2>
            <ul class="list-disc space-y-1 pl-5">
                <li>The content you paste into the decoder</li>
                <li>SAML assertions, JWTs, certificates, or any identity data</li>
                <li>IP addresses, usage patterns, or behavioral analytics</li>
                <li>Account information (there are no accounts)</li>
            </ul>
        </section>

        <section class="space-y-2">
            <h2 class="text-base font-semibold text-neutral-900 dark:text-neutral-100">
                OIDC discovery proxy
            </h2>
            <p>
                The planned OIDC discovery feature sends an issuer URL to a server-side proxy, which
                fetches the issuer's <code
                    class="rounded bg-neutral-100 px-1 font-mono text-xs dark:bg-neutral-800"
                    >.well-known/openid-configuration</code
                > endpoint on your behalf to avoid browser CORS restrictions. The proxy forwards the
                response and does not log or store the issuer URL or the response.
            </p>
        </section>

        <section class="space-y-2">
            <h2 class="text-base font-semibold text-neutral-900 dark:text-neutral-100">
                Local storage
            </h2>
            <p>
                Your light/dark theme preference is saved to <code
                    class="rounded bg-neutral-100 px-1 font-mono text-xs dark:bg-neutral-800"
                    >localStorage</code
                > in your browser. This value never leaves your device.
            </p>
        </section>

        <section class="space-y-2">
            <h2 class="text-base font-semibold text-neutral-900 dark:text-neutral-100">
                Hosting
            </h2>
            <p>
                This site is served via Cloudflare Pages. Cloudflare may collect standard web server
                logs (IP address, request path, timestamp) in accordance with their own <a
                    href="https://www.cloudflare.com/privacypolicy/"
                    class="underline decoration-neutral-400 underline-offset-2 hover:decoration-neutral-600"
                    target="_blank"
                    rel="noopener noreferrer">privacy policy</a
                >. samlguy.com does not have access to those logs.
            </p>
        </section>

        <section class="space-y-2">
            <h2 class="text-base font-semibold text-neutral-900 dark:text-neutral-100">Contact</h2>
            <p>
                Questions about this policy can be sent to <a
                    href="mailto:samlguy@kellenmurphy.com"
                    class="underline decoration-neutral-400 underline-offset-2 hover:decoration-neutral-600"
                    >samlguy@kellenmurphy.com</a
                >.
            </p>
        </section>
    </div>
</div>
