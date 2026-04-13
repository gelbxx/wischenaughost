/**
 * Network status type definitions for WischenauGhost.
 */

/** The current state of the P2P node. */
export enum NodeStatus {
  /** Node is not running. */
  Stopped = 'stopped',
  /** Node is starting up (connecting to bootstrap, joining DHT). */
  Starting = 'starting',
  /** Node is online and connected to the P2P network. */
  Online = 'online',
  /** Node lost connection and is attempting to reconnect. */
  Reconnecting = 'reconnecting',
}

/** Connection info for a specific peer. */
export interface PeerConnection {
  peerId: string;
  /** How we're connected to this peer. */
  connectionType: 'direct' | 'relay' | 'lan';
  /** Is the connection currently active? */
  isConnected: boolean;
  /** Round-trip latency in milliseconds. */
  latencyMs?: number;
}

/** Overall network status shown in the UI. */
export interface NetworkStatus {
  nodeStatus: NodeStatus;
  /** Number of peers we're connected to in the DHT. */
  connectedPeers: number;
  /** Our multiaddress on the network. */
  listenAddress?: string;
  /** Whether we're behind NAT. */
  behindNat: boolean;
}
