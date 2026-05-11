export interface CertInfo {
    subject: string;
    issuer: string;
    validFrom: Date;
    validTo: Date;
    isValid: boolean;
    serialNumber: string;
    keyAlgorithm: string;
}

const OID_ATTR: Record<string, string> = {
    '2.5.4.3': 'CN',
    '2.5.4.6': 'C',
    '2.5.4.7': 'L',
    '2.5.4.8': 'ST',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
    '1.2.840.113549.1.9.1': 'emailAddress'
};

const OID_SPKI: Record<string, string> = {
    '1.2.840.113549.1.1.1': 'RSA',
    '1.2.840.10045.2.1': 'EC'
};

const OID_CURVE: Record<string, string> = {
    '1.2.840.10045.3.1.7': 'P-256',
    '1.3.132.0.34': 'P-384',
    '1.3.132.0.35': 'P-521'
};

interface DerNode {
    tag: number;
    value: Uint8Array;
    children?: DerNode[];
}

function readLength(b: Uint8Array, o: number): { len: number; next: number } {
    const first = b[o];
    if (!(first & 0x80)) return { len: first, next: o + 1 };
    const n = first & 0x7f;
    let len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | b[o + 1 + i];
    return { len, next: o + 1 + n };
}

function parseNode(b: Uint8Array, o: number): { node: DerNode; next: number } {
    const tag = b[o];
    const { len, next: vs } = readLength(b, o + 1);
    const value = b.slice(vs, vs + len);
    let children: DerNode[] | undefined;
    if (tag & 0x20) {
        children = [];
        let pos = 0;
        while (pos < value.length) {
            const { node, next } = parseNode(value, pos);
            children.push(node);
            pos = next;
        }
    }
    return { node: { tag, value, children }, next: vs + len };
}

function oid(bytes: Uint8Array): string {
    const parts: number[] = [];
    let first = true;
    let acc = 0;
    for (const b of bytes) {
        acc = (acc << 7) | (b & 0x7f);
        if (!(b & 0x80)) {
            if (first) { parts.push(Math.floor(acc / 40), acc % 40); first = false; }
            else parts.push(acc);
            acc = 0;
        }
    }
    return parts.join('.');
}

function str(node: DerNode): string {
    return new TextDecoder().decode(node.value);
}

function parseTime(node: DerNode): Date {
    const s = str(node);
    if (node.tag === 0x17) {
        const y = parseInt(s.slice(0, 2));
        return new Date(
            `${y >= 50 ? 1900 + y : 2000 + y}-${s.slice(2, 4)}-${s.slice(4, 6)}` +
            `T${s.slice(6, 8)}:${s.slice(8, 10)}:${s.slice(10, 12)}Z`
        );
    }
    return new Date(
        `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}` +
        `T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`
    );
}

function parseName(node: DerNode): string {
    /* v8 ignore next */
    const rdns = node.children ?? [];
    return rdns
        .flatMap((rdn) => {
            /* v8 ignore next */
            const atvs = rdn.children ?? [];
            return atvs.map((atv) => {
                /* v8 ignore next */
                if (!atv.children || atv.children.length < 2) return '';
                const name = OID_ATTR[oid(atv.children[0].value)] ?? oid(atv.children[0].value);
                return `${name}=${str(atv.children[1])}`;
            });
        })
        .filter(Boolean)
        .join(', ');
}

function parseKeyAlg(spki: DerNode): string {
    const algId = spki.children?.[0];
    /* v8 ignore next */
    if (!algId?.children?.[0]) return 'Unknown';
    const algOid = oid(algId.children[0].value);
    const name = OID_SPKI[algOid];
    if (!name) return algOid;

    if (name === 'EC') {
        const curveOid = algId.children[1] ? oid(algId.children[1].value) : '';
        return `EC ${OID_CURVE[curveOid] ?? curveOid}`;
    }

    /* v8 ignore next */
    if (name === 'RSA') {
        const bitStr = spki.children?.[1];
        /* v8 ignore next */
        if (bitStr) {
            try {
                const { node: rsaKey } = parseNode(bitStr.value.slice(1), 0);
                const mod = rsaKey.children?.[0];
                if (mod) {
                    const bits = (mod.value.length - (mod.value[0] === 0 ? 1 : 0)) * 8;
                    return `RSA-${bits}`;
                }
            } catch {
                // fall through to name
            }
        }
    }

    return name;
}

export function decodeCert(base64Der: string): CertInfo {
    const binary = atob(base64Der.replace(/\s+/g, ''));
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));

    const { node: cert } = parseNode(bytes, 0);
    const tbs = cert.children![0];
    const f = tbs.children!;

    let i = 0;
    if (f[0].tag === 0xa0) i++; // skip optional version

    const rawSerial = f[i++].value;
    const serialNumber = Array.from(rawSerial[0] === 0 ? rawSerial.slice(1) : rawSerial)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(':');

    i++; // skip signature algorithm
    const issuer = parseName(f[i++]);
    const validity = f[i++];
    const validFrom = parseTime(validity.children![0]);
    const validTo = parseTime(validity.children![1]);
    const subject = parseName(f[i++]);
    const keyAlgorithm = parseKeyAlg(f[i]);

    const now = new Date();
    return { subject, issuer, validFrom, validTo, isValid: now >= validFrom && now <= validTo, serialNumber, keyAlgorithm };
}
