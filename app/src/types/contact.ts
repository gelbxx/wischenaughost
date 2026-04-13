/**
 * Contact type definitions for WischenauGhost.
 */

import {PeerId} from './message';

/** How a contact's identity has been verified. */
export enum TrustLevel {
  /** Public key received but not independently verified. */
  Unverified = 'unverified',
  /** Verified via in-person QR code scan. */
  VerifiedInPerson = 'verified_in_person',
  /** Verified via a trusted mutual contact. */
  VerifiedByMutual = 'verified_by_mutual',
}

/** A contact in the user's friend list. */
export interface Contact {
  peerId: PeerId;
  displayName: string;
  /** Base64-encoded avatar image. */
  avatar?: string;
  statusText?: string;
  trustLevel: TrustLevel;
  isBlocked: boolean;
  addedAt: number;
  lastSeen?: number;
  /** Whether this contact's identity key has changed since verification. */
  identityKeyChanged: boolean;
}

/** A conversation (1-on-1 or group). */
export interface Conversation {
  id: string;
  type: 'direct' | 'group';
  /** For direct: the contact's peer ID. For groups: the group ID. */
  peerId?: PeerId;
  groupId?: string;
  name: string;
  avatar?: string;
  lastMessageText?: string;
  lastMessageTimestamp?: number;
  unreadCount: number;
  isPinned: boolean;
  isMuted: boolean;
}
