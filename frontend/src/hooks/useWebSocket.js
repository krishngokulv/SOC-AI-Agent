import { useState, useEffect, useCallback, useRef } from 'react';
import { WS_BASE_URL } from '../utils/constants';

/**
 * WebSocket hook for real-time investigation streaming.
 *
 * Connects to /ws/investigate/{id}, buffers events,
 * handles reconnection with exponential backoff.
 */
export function useWebSocket(investigationId, options = {}) {
  const {
    autoConnect = true,
    maxReconnectAttempts = 5,
    baseReconnectDelay = 1000,
    onMessage = null,
    onStageChange = null,
    onComplete = null,
    onError = null,
  } = options;

  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [events, setEvents] = useState([]);
  const [currentStage, setCurrentStage] = useState(null);
  const [stages, setStages] = useState({});
  const [verdict, setVerdict] = useState(null);
  const [enrichmentResults, setEnrichmentResults] = useState([]);
  const [isComplete, setIsComplete] = useState(false);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState(0);

  const wsRef = useRef(null);
  const reconnectAttempts = useRef(0);
  const reconnectTimer = useRef(null);
  const mountedRef = useRef(true);
  const eventBufferRef = useRef([]);

  // Process incoming WebSocket message
  const processMessage = useCallback(
    (event) => {
      try {
        const data = JSON.parse(event.data);

        if (!mountedRef.current) return;

        // Add to event buffer
        eventBufferRef.current.push(data);
        setEvents((prev) => [...prev, data]);

        // Handle different event types
        switch (data.type) {
          case 'stage_start': {
            const stageKey = data.stage;
            setCurrentStage(stageKey);
            setStages((prev) => ({
              ...prev,
              [stageKey]: {
                status: 'running',
                startTime: Date.now(),
                data: data.data || null,
              },
            }));
            if (onStageChange) onStageChange(stageKey, 'running', data);
            break;
          }

          case 'stage_complete': {
            const stageKey = data.stage;
            setStages((prev) => ({
              ...prev,
              [stageKey]: {
                ...prev[stageKey],
                status: 'complete',
                endTime: Date.now(),
                duration: data.duration,
                data: data.data || prev[stageKey]?.data,
                result: data.result || null,
              },
            }));
            if (onStageChange) onStageChange(stageKey, 'complete', data);
            break;
          }

          case 'stage_error': {
            const stageKey = data.stage;
            setStages((prev) => ({
              ...prev,
              [stageKey]: {
                ...prev[stageKey],
                status: 'error',
                error: data.error,
                endTime: Date.now(),
              },
            }));
            if (onStageChange) onStageChange(stageKey, 'error', data);
            break;
          }

          case 'enrichment_result': {
            setEnrichmentResults((prev) => [
              ...prev,
              {
                source: data.source,
                ioc: data.ioc,
                result: data.result,
                timestamp: Date.now(),
              },
            ]);
            break;
          }

          case 'progress': {
            setProgress(data.progress || 0);
            break;
          }

          case 'verdict': {
            setVerdict({
              verdict: data.verdict,
              confidence: data.confidence,
              reasoning: data.reasoning,
              summary: data.summary,
            });
            break;
          }

          case 'complete': {
            setIsComplete(true);
            setProgress(100);
            if (onComplete) onComplete(data);
            break;
          }

          case 'error': {
            setError(data.message || 'Investigation error');
            if (onError) onError(data);
            break;
          }

          case 'heartbeat':
            // Ignore heartbeats
            break;

          default:
            console.log('[WS] Unknown event type:', data.type);
        }

        // Call generic message handler
        if (onMessage) onMessage(data);
      } catch (parseError) {
        console.error('[WS] Failed to parse message:', parseError);
      }
    },
    [onMessage, onStageChange, onComplete, onError]
  );

  // Connect to WebSocket
  const connect = useCallback(() => {
    if (!investigationId || wsRef.current?.readyState === WebSocket.OPEN) return;

    setConnecting(true);
    setError(null);

    const wsUrl = `${WS_BASE_URL}/ws/investigate/${investigationId}`;
    console.log(`[WS] Connecting to ${wsUrl}`);

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;
        console.log('[WS] Connected');
        setConnected(true);
        setConnecting(false);
        reconnectAttempts.current = 0;
      };

      ws.onmessage = processMessage;

      ws.onclose = (closeEvent) => {
        if (!mountedRef.current) return;
        console.log(`[WS] Disconnected (code: ${closeEvent.code})`);
        setConnected(false);
        setConnecting(false);

        // Attempt reconnection if not a clean close and not complete
        if (
          closeEvent.code !== 1000 &&
          !isComplete &&
          reconnectAttempts.current < maxReconnectAttempts
        ) {
          const delay =
            baseReconnectDelay * Math.pow(2, reconnectAttempts.current);
          console.log(
            `[WS] Reconnecting in ${delay}ms (attempt ${reconnectAttempts.current + 1})`
          );
          reconnectTimer.current = setTimeout(() => {
            reconnectAttempts.current += 1;
            connect();
          }, delay);
        }
      };

      ws.onerror = (wsError) => {
        if (!mountedRef.current) return;
        console.error('[WS] Error:', wsError);
        setError('WebSocket connection error');
        setConnecting(false);
      };
    } catch (err) {
      console.error('[WS] Failed to create connection:', err);
      setConnecting(false);
      setError('Failed to establish WebSocket connection');
    }
  }, [
    investigationId,
    processMessage,
    isComplete,
    maxReconnectAttempts,
    baseReconnectDelay,
  ]);

  // Disconnect
  const disconnect = useCallback(() => {
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current);
      reconnectTimer.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close(1000, 'Client disconnect');
      wsRef.current = null;
    }
    setConnected(false);
    setConnecting(false);
  }, []);

  // Send message to server
  const send = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
    }
  }, []);

  // Reset state
  const reset = useCallback(() => {
    disconnect();
    setEvents([]);
    setStages({});
    setCurrentStage(null);
    setVerdict(null);
    setEnrichmentResults([]);
    setIsComplete(false);
    setError(null);
    setProgress(0);
    eventBufferRef.current = [];
    reconnectAttempts.current = 0;
  }, [disconnect]);

  // Auto-connect on mount
  useEffect(() => {
    mountedRef.current = true;

    if (autoConnect && investigationId) {
      connect();
    }

    return () => {
      mountedRef.current = false;
      disconnect();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [investigationId]);

  return {
    connected,
    connecting,
    events,
    currentStage,
    stages,
    verdict,
    enrichmentResults,
    isComplete,
    error,
    progress,
    connect,
    disconnect,
    send,
    reset,
  };
}

export default useWebSocket;
