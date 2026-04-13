/**
 * CryptoService — bridge between the TypeScript UI and the Rust crypto layer.
 *
 * All cryptographic operations (key generation, encryption, decryption)
 * happen inside the Rust wghost-crypto crate. This service calls into
 * that native module via the uniffi FFI bridge.
 *
 * The UI never touches raw keys or crypto primitives directly.
 */

import type {OwnIdentity, SafetyNumber} from '../types';

// TODO: Replace with real uniffi TurboModule import once FFI bridge is built
// import {WGhostCrypto} from '../../../rust/wghost-ffi';

/**
 * Generate a new identity key pair for the user.
 * Called once when the app is first opened.
 */
export async function generateIdentity(): Promise<OwnIdentity> {
  // TODO: Call into Rust via FFI
  throw new Error('Not yet implemented — Week 1-2 (Phase 1)');
}

/**
 * Load the existing identity from secure storage.
 * Returns null if no identity has been created yet.
 */
export async function loadIdentity(): Promise<OwnIdentity | null> {
  // TODO: Call into Rust via FFI
  throw new Error('Not yet implemented — Week 1-2 (Phase 1)');
}

/**
 * Compute the safety number between our identity and a contact's identity.
 * Used for in-person verification.
 */
export async function computeSafetyNumber(
  contactPeerId: string,
): Promise<SafetyNumber> {
  // TODO: Call into Rust via FFI
  throw new Error('Not yet implemented — Week 3-4 (Phase 1)');
}
