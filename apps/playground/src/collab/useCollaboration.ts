/**
 * React hook for WebRTC collaborative editing
 */

import { useRef, useCallback, useState, useEffect } from 'react';
import { WebRTCCollaborationProvider, type Collaborator, type WebRTCProviderOptions } from './webrtc-provider';
import type { Diagnostic } from '../types';

export interface UseCollaborationOptions extends WebRTCProviderOptions {
  enabled?: boolean;
}

export interface UseCollaborationReturn {
  provider: WebRTCCollaborationProvider | null;
  collaborators: Collaborator[];
  isConnected: boolean;
  isSynced: boolean;
  roomId: string;
  username: string;
  setUsername: (username: string) => void;
  setDiagnostics: (diagnostics: Diagnostic[]) => void;
  getDiagnostics: () => Diagnostic[];
  connect: () => void;
  disconnect: () => void;
}

export function useCollaboration(options: UseCollaborationOptions = {}): UseCollaborationReturn {
  const {
    enabled = true,
    roomId,
    signalingServers,
    username,
    onCollaboratorsChange,
    onConnectionChange,
    onSyncChange,
  } = options;

  const providerRef = useRef<WebRTCCollaborationProvider | null>(null);
  const [collaborators, setCollaborators] = useState<Collaborator[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isSynced, setIsSynced] = useState(false);
  const [currentRoomId, setCurrentRoomId] = useState<string>('');
  const [currentUsername, setCurrentUsername] = useState<string>('');

  const handleCollaboratorsChange = useCallback((collabs: Collaborator[]) => {
    setCollaborators(collabs);
    onCollaboratorsChange?.(collabs);
  }, [onCollaboratorsChange]);

  const handleConnectionChange = useCallback((connected: boolean) => {
    setIsConnected(connected);
    onConnectionChange?.(connected);
  }, [onConnectionChange]);

  const handleSyncChange = useCallback((synced: boolean) => {
    setIsSynced(synced);
    onSyncChange?.(synced);
  }, [onSyncChange]);

  useEffect(() => {
    if (!enabled) return;

    const provider = new WebRTCCollaborationProvider({
      roomId,
      signalingServers,
      username,
      onCollaboratorsChange: handleCollaboratorsChange,
      onConnectionChange: handleConnectionChange,
      onSyncChange: handleSyncChange,
    });

    providerRef.current = provider;
    setCurrentRoomId(provider.getRoomId());
    setCurrentUsername(provider.getUsername());

    return () => {
      provider.destroy();
      providerRef.current = null;
    };
  }, [enabled, roomId, signalingServers, username, handleCollaboratorsChange, handleConnectionChange, handleSyncChange]);

  const connect = useCallback(() => {
    providerRef.current?.connect();
  }, []);

  const disconnect = useCallback(() => {
    providerRef.current?.disconnect();
  }, []);

  const setUsername = useCallback((newUsername: string) => {
    providerRef.current?.setUsername(newUsername);
    setCurrentUsername(newUsername);
  }, []);

  const setDiagnostics = useCallback((diagnostics: Diagnostic[]) => {
    providerRef.current?.setDiagnostics(diagnostics);
  }, []);

  const getDiagnostics = useCallback(() => {
    return providerRef.current?.getDiagnostics() ?? [];
  }, []);

  return {
    provider: providerRef.current,
    collaborators,
    isConnected,
    isSynced,
    roomId: currentRoomId,
    username: currentUsername,
    setUsername,
    setDiagnostics,
    getDiagnostics,
    connect,
    disconnect,
  };
}