<svelte:head>
    <title>Privacy Policy — samlguy.com</title>
    <meta name="description" content="Privacy policy for samlguy.com." />
</svelte:head>

<div class="prose prose-neutral max-w-2xl dark:prose-invert">
    <h1 class="text-2xl font-bold">Privacy Policy</h1>
    <p class="mt-1 text-sm text-neutral-500">Effective: May 2025</p>

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
