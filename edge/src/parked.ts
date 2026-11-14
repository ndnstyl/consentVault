// The one list of answers that mean the vault has no running connector (the tunnel is gone), shared by the sign-in route and the portal.
// The vault's own 503 (a gate that fails closed) is an answer, not a parked vault.
export const PARKED_STATUSES = new Set([502, 504, 520, 521, 522, 523, 524, 525, 526, 527, 530]);
