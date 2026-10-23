import { useEffect, useRef, useCallback } from "react";

type UseWebSocketOptions = {
  /** Initial retry delay in ms. Doubles on each failure up to maxDelay. */
  initialDelay?: number;
  /** Hard ceiling on retry delay in ms. Default 30 000. */
  maxDelay?: number;
  /**
   * Called when the socket opens (or re-opens after a reconnect).
   * Use this to re-subscribe or re-send any auth frame.
   */
  onOpen?: (event: Event) => void;
  /** Called on every incoming message, before JSON parsing. */
  onError?: (event: Event) => void;
};

/**
 * Persistent WebSocket with exponential-backoff reconnect.
 *
 * Usage:
 *   const { sendMessage, close } = useWebSocket<Alert>(
 *     "ws://localhost:8000/ws/alerts",
 *     (alert) => setAlerts(prev => [alert, ...prev].slice(0, 10)),
 *   );
 *
 * The hook owns the socket lifetime.  Pass a stable `onMessage` ref
 * (wrap with useCallback) to avoid unnecessary re-connects.
 */
export function useWebSocket<T>(
  url: string,
  onMessage: (data: T) => void,
  options: UseWebSocketOptions = {},
) {
  const {
    initialDelay = 1_000,
    maxDelay = 30_000,
    onOpen,
    onError,
  } = options;

  const socketRef = useRef<WebSocket | null>(null);
  const retryDelay = useRef(initialDelay);
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const destroyed = useRef(false);

  // Keep callbacks in refs so the socket handlers always call the latest version
  // without needing to reconnect when the parent re-renders.
  const onMessageRef = useRef(onMessage);
  const onOpenRef = useRef(onOpen);
  const onErrorRef = useRef(onError);
  onMessageRef.current = onMessage;
  onOpenRef.current = onOpen;
  onErrorRef.current = onError;

  const connect = useCallback(() => {
    if (destroyed.current) return;

    const ws = new WebSocket(url);
    socketRef.current = ws;

    ws.onopen = (event) => {
      retryDelay.current = initialDelay; // reset backoff on successful connect
      onOpenRef.current?.(event);
    };

    ws.onmessage = (event) => {
      try {
        const parsed: T = JSON.parse(event.data as string);
        onMessageRef.current(parsed);
      } catch {
        // Non-JSON frame — ignore or log.
      }
    };

    ws.onerror = (event) => {
      onErrorRef.current?.(event);
    };

    ws.onclose = () => {
      if (destroyed.current) return;
      retryTimer.current = setTimeout(() => {
        connect();
      }, retryDelay.current);
      // Exponential backoff, capped.
      retryDelay.current = Math.min(retryDelay.current * 2, maxDelay);
    };
  }, [url, initialDelay, maxDelay]);

  useEffect(() => {
    destroyed.current = false;
    connect();

    return () => {
      destroyed.current = true;
      if (retryTimer.current !== null) clearTimeout(retryTimer.current);
      socketRef.current?.close();
    };
  }, [connect]);

  /** Send a raw string frame. No-ops if the socket isn't open. */
  const sendMessage = useCallback((message: string) => {
    if (socketRef.current?.readyState === WebSocket.OPEN) {
      socketRef.current.send(message);
    }
  }, []);

  /** Permanently close the socket (tears down the hook). */
  const close = useCallback(() => {
    destroyed.current = true;
    if (retryTimer.current !== null) clearTimeout(retryTimer.current);
    socketRef.current?.close();
  }, []);

  return { sendMessage, close };
}
