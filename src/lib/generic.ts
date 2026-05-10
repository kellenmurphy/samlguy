import { inflateRaw } from 'pako';
import { prettyPrintXml } from './saml';

export type GenericEncoding = 'base64+deflate' | 'base64' | 'text';
export type GenericContentType = 'xml' | 'json' | 'text';

export interface GenericDecodeResult {
    content: string;
    encoding: GenericEncoding;
    contentType: GenericContentType;
}

function safeDecode(s: string): string {
    try {
        return decodeURIComponent(s);
    } catch {
        return s;
    }
}

function base64ToBytes(b64: string): Uint8Array {
    const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '=='.slice(0, (4 - (normalized.length % 4)) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function detectContentType(text: string): GenericContentType {
    const t = text.trimStart();
    if (t.startsWith('<')) return 'xml';
    if (t.startsWith('{') || t.startsWith('[')) return 'json';
    return 'text';
}

function isReadable(text: string): boolean {
    if (!text) return false;
    const sample = text.slice(0, 500);
    let bad = 0;
    for (let i = 0; i < sample.length; i++) {
        const c = sample.charCodeAt(i);
        if (c < 0x09 || (c > 0x0d && c < 0x20) || c === 0x7f || c === 0xfffd) bad++;
    }
    return bad / sample.length < 0.05;
}

function formatContent(text: string, ct: GenericContentType): string {
    if (ct === 'xml') return prettyPrintXml(text);
    if (ct === 'json') {
        try {
            return JSON.stringify(JSON.parse(text), null, 4);
        } catch {
            return text;
        }
    }
    return text;
}

function tryBase64(raw: string): GenericDecodeResult | null {
    let value = raw.trim();
    for (let i = 0; i < 5; i++) {
        const next = safeDecode(value);
        if (next === value) break;
        value = next;
    }

    const b64 = value.replace(/\s+/g, '');
    if (b64.length < 8 || !/^[A-Za-z0-9+/\-_=]+$/.test(b64)) return null;

    let bytes: Uint8Array;
    try {
        bytes = base64ToBytes(b64);
    } catch {
        return null;
    }

    // Try raw DEFLATE (HTTP-Redirect binding style)
    try {
        const inflated = inflateRaw(bytes);
        const text = new TextDecoder().decode(inflated);
        if (isReadable(text)) {
            const ct = detectContentType(text);
            return { content: formatContent(text, ct), encoding: 'base64+deflate', contentType: ct };
        }
    } catch {
        // not deflated
    }

    // Try plain base64 (HTTP-POST binding style)
    const text = new TextDecoder().decode(bytes);
    if (isReadable(text)) {
        const ct = detectContentType(text);
        return { content: formatContent(text, ct), encoding: 'base64', contentType: ct };
    }

    return null;
}

export function decodeAllGeneric(raw: string): GenericDecodeResult[] {
    const results: GenericDecodeResult[] = [];
    const seenContent = new Set<string>();

    function add(r: GenericDecodeResult | null) {
        if (!r) return;
        const key = r.content.slice(0, 80);
        if (!seenContent.has(key)) {
            seenContent.add(key);
            results.push(r);
        }
    }

    const input = raw.trim();

    // Already readable text — XML, JSON, or plain
    if (input.startsWith('<') || input.startsWith('{') || input.startsWith('[')) {
        const ct = detectContentType(input);
        add({ content: formatContent(input, ct), encoding: 'text', contentType: ct });
        return results;
    }

    // Try URL/query string params — only when the input has a plausible key=value structure
    // (avoids misidentifying raw base64 blobs that happen to contain padding '=')
    let qs: string | null = null;
    try {
        const url = new URL(input);
        if (url.search) qs = url.search;
    } catch {
        const eqIdx = input.indexOf('=');
        if (input.startsWith('?')) {
            qs = input;
        } else if (
            eqIdx > 0 &&
            eqIdx <= 60 &&
            /^[A-Za-z]\w*$/.test(input.slice(0, eqIdx)) &&
            !input.includes('\n')
        ) {
            qs = `?${input}`;
        }
    }

    if (qs) {
        for (const [, value] of new URLSearchParams(qs)) {
            add(tryBase64(value));
        }
    }

    // Scan for base64-looking blobs of significant length (≥80 chars)
    const blobRe = /[A-Za-z0-9+/\-_]{80,}={0,2}/g;
    let m: RegExpExecArray | null;
    while ((m = blobRe.exec(raw)) !== null) {
        add(tryBase64(m[0]));
    }

    // Final fallback: try the whole input as a single blob
    // (catches short blobs below the ≥80-char scan threshold)
    add(tryBase64(input));

    return results;
}
