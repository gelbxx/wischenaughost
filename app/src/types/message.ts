/**
 * Message type definitions for WischenauGhost.
 *
 * These mirror the protobuf definitions in proto/message.proto
 * but as TypeScript types for use in the UI layer.
 */

/** Unique identifier for a message (UUID v4). */
export type MessageId = string;

/** Peer identifier (Base32-encoded public key hash). */
export type PeerId = string;

/** Message delivery status. */
export enum MessageStatus {
  /** Message is in the local outbox, waiting to be sent. */
  Pending = 'pending',
  /** Message has left the device (sent to peer or mailbox). */
  Sent = 'sent',
  /** Recipient's device confirmed receipt. */
  Delivered = 'delivered',
  /** Recipient has read the message. */
  Read = 'read',
  /** Message could not be delivered. */
  Failed = 'failed',
}

/** The content type of a message. */
export enum MessageType {
  Text = 'text',
  Image = 'image',
  File = 'file',
}

/** A single chat message. */
export interface Message {
  id: MessageId;
  conversationId: string;
  senderPeerId: PeerId;
  type: MessageType;
  status: MessageStatus;
  timestamp: number;

  /** Text content (for text messages). */
  text?: string;

  /** Reply to another message. */
  replyToMessageId?: MessageId;

  /** File metadata (for file/image messages). */
  file?: FileAttachment;
}

/** File attachment metadata. */
export interface FileAttachment {
  filename: string;
  mimeType: string;
  size: number;
  /** Base64-encoded thumbnail (for images). */
  thumbnail?: string;
  width?: number;
  height?: number;
}
