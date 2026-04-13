/**
 * StorageService — bridge to the Rust SQLCipher storage layer.
 *
 * All database operations run in Rust via wghost-storage.
 * The database is AES-256 encrypted at rest via SQLCipher.
 */

import type {Message, Contact, Conversation} from '../types';

// TODO: Replace with real uniffi TurboModule import
// import {WGhostStorage} from '../../../rust/wghost-ffi';

/**
 * Get all conversations, sorted by last message timestamp.
 */
export async function getConversations(): Promise<Conversation[]> {
  // TODO: Call into Rust via FFI
  return [];
}

/**
 * Get messages for a conversation, newest-first with pagination.
 */
export async function getMessages(
  conversationId: string,
  limit: number,
  offset: number,
): Promise<Message[]> {
  // TODO: Call into Rust via FFI
  return [];
}

/**
 * Search messages using SQLite FTS5 full-text search.
 * Search is entirely local — no data leaves the device.
 */
export async function searchMessages(query: string): Promise<Message[]> {
  // TODO: Call into Rust via FFI
  return [];
}

/**
 * Get all contacts, sorted by display name.
 */
export async function getContacts(): Promise<Contact[]> {
  // TODO: Call into Rust via FFI
  return [];
}
