export type SignatureKind = 'ed25519' | 'hmac';

export function isHmac(kind: SignatureKind): boolean {
  switch (kind) {
    case 'hmac': return true;
    case 'ed25519': return false;
  }
}

export const isEd25519 = (kind: SignatureKind): boolean => !isHmac(kind);
