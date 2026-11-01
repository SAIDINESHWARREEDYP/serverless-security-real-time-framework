import { useState, useEffect, useRef, useCallback } from 'react';
import { SecurityAuditLog, AnomalyAlert } from '../types.ts';

export type RealtimeConnectionStatus = 'LIVE_STREAMING' | 'POLLING_FALLBACK' | 'RECONNECTING';

interface RealtimeMonitorOptions {
  onNewLog?: (log: SecurityAuditLog) => void;
  onNewAlert?: (alert: any) => void;
  onIncidentUpdate?: (incident: any) => void;
  pollingIntervalMs?: number;
}

export function useRealtimeMonitor(options: RealtimeMonitorOptions = {}) {
  const { onNewLog, onNewAlert, onIncidentUpdate, pollingIntervalMs = 4000 } = options;
  const [connectionStatus, setConnectionStatus] = useState<RealtimeConnectionStatus>('RECONNECTING');
  const [lastServerTime, setLastServerTime] = useState<string>(new Date().toISOString());
  const [streamEventsCount, setStreamEventsCount] = useState<number>(0);
  const [reconnectAttempts, setReconnectAttempts] = useState<number>(0);

  // Set of seen event IDs to prevent duplicate processing
  const processedEventIdsRef = useRef<Set<string>>(new Set());

  // SSE event source ref
  const eventSourceRef = useRef<EventSource | null>(null);
  const isPollingFallbackRef = useRef<boolean>(false);
  const pollingTimerRef = useRef<any>(null);

  const processIncomingEvent = useCallback((event: { type: string; data: any; timestamp: string }) => {
    setLastServerTime(event.timestamp || new Date().toISOString());
    setStreamEventsCount(prev => prev + 1);

    if (event.type === 'NEW_INVOCATION' && event.data) {
      const eventKey = `log_${event.data.id}_${event.data.timestamp}`;
      if (!processedEventIdsRef.current.has(eventKey)) {
        processedEventIdsRef.current.add(eventKey);
        if (onNewLog) onNewLog(event.data);
      }
    } else if (event.type === 'THREAT_ALERT' && event.data) {
      const eventKey = `alt_${event.data.id}`;
      if (!processedEventIdsRef.current.has(eventKey)) {
        processedEventIdsRef.current.add(eventKey);
        if (onNewAlert) onNewAlert(event.data);
      }
    } else if ((event.type === 'INCIDENT_CREATED' || event.type === 'INCIDENT_UPDATED') && event.data) {
      if (onIncidentUpdate) onIncidentUpdate(event.data);
    }
  }, [onNewLog, onNewAlert, onIncidentUpdate]);

  // Connect to SSE stream with automated polling fallback
  useEffect(() => {
    let isCancelled = false;

    const startPollingFallback = () => {
      if (isCancelled) return;
      isPollingFallbackRef.current = true;
      setConnectionStatus('POLLING_FALLBACK');

      const poll = async () => {
        try {
          const res = await fetch('/api/system/health');
          if (res.ok) {
            const data = await res.json();
            setLastServerTime(data.timestamp || new Date().toISOString());
          }
        } catch {
          // ignore transient poll failure
        }
      };

      poll();
      pollingTimerRef.current = setInterval(poll, pollingIntervalMs);
    };

    const initEventSource = () => {
      try {
        const es = new EventSource('/api/v1/realtime/stream');
        eventSourceRef.current = es;

        es.onopen = () => {
          if (!isCancelled) {
            setConnectionStatus('LIVE_STREAMING');
            setReconnectAttempts(0);
            if (pollingTimerRef.current) {
              clearInterval(pollingTimerRef.current);
              pollingTimerRef.current = null;
            }
          }
        };

        es.onmessage = (e) => {
          if (isCancelled) return;
          try {
            const parsed = JSON.parse(e.data);
            processIncomingEvent(parsed);
          } catch {
            // non-json or heartbeat message
          }
        };

        es.onerror = () => {
          if (!isCancelled) {
            es.close();
            setConnectionStatus('RECONNECTING');
            setReconnectAttempts(prev => prev + 1);

            // Reconnection strategy with backoff; fallback to controlled polling
            setTimeout(() => {
              if (!isCancelled) {
                startPollingFallback();
              }
            }, 3000);
          }
        };
      } catch {
        startPollingFallback();
      }
    };

    initEventSource();

    return () => {
      isCancelled = true;
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
      if (pollingTimerRef.current) {
        clearInterval(pollingTimerRef.current);
      }
    };
  }, [pollingIntervalMs, processIncomingEvent]);

  return {
    connectionStatus,
    lastServerTime,
    streamEventsCount,
    reconnectAttempts,
    isLive: connectionStatus === 'LIVE_STREAMING'
  };
}
