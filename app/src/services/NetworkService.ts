/**
 * NetworkService — bridge between the TypeScript UI and the Rust network layer.
 *
 * All P2P networking runs inside the Rust wghost-network crate.
 * This service exposes a clean async API for the UI to use.
 */

import type {NetworkStatus} from '../types';

// TODO: Replace with real uniffi TurboModule import
// import {WGhostNetwork} from '../../../rust/wghost-ffi';

/**
 * Start the P2P node. Should be called when the app foregrounds.
 */
export async function startNode(): Promise<void> {
  // TODO: Call into Rust via FFI
  throw new Error('Not yet implemented — Week 5-6 (Phase 1)');
}

/**
 * Stop the P2P node gracefully. Called when app backgrounds.
 */
export async function stopNode(): Promise<void> {
  // TODO: Call into Rust via FFI
  throw new Error('Not yet implemented — Week 5-6 (Phase 1)');
}

/**
 * Get the current network status (online, connecting, etc.).
 */
export async function getNetworkStatus(): Promise<NetworkStatus> {
  // TODO: Call into Rust via FFI
  throw new Error('Not yet implemented — Week 5-6 (Phase 1)');
}

/**
 * Send a message to a peer. If they're offline, queues it for mailbox delivery.
 */
export async function sendMessage(
  recipientPeerId: string,
  encryptedEnvelope: Uint8Array,
): Promise<void> {
  // TODO: Call into Rust via FFI
  throw new Error('Not yet implemented — Week 9-10 (Phase 2)');
}
