/**
 * Crypto-related type definitions for WischenauGhost.
 */

/** Our own identity (private + public keys). */
export interface OwnIdentity {
  /** Our peer ID (derived from public key). */
  peerId: string;
  /** Human-readable address: wg:XXXX-XXXX-XXXX-XXXX */
  address: string;
  /** Whether the identity key is backed up. */
  isBackedUp: boolean;
}

/** Safety number for verifying a contact's identity. */
export interface SafetyNumber {
  /** 60-digit numeric string (groups of 5). */
  numericCode: string;
  /** QR code data for scanning. */
  qrCodeData: string;
}
