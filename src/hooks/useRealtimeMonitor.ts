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

  const onNewLogRef = useRef(onNewLog);
  const onNewAlertRef = useRef(onNewAlert);
  const onIncidentUpdateRef = useRef(onIncidentUpdate);

  useEffect(() => {
    onNewLogRef.current = onNewLog;
    onNewAlertRef.current = onNewAlert;
    onIncidentUpdateRef.current = onIncidentUpdate;
  }, [onNewLog, onNewAlert, onIncidentUpdate]);

  // Set of seen event IDs to prevent duplicate processing (bounded to prevent memory growth)
  const processedEventIdsRef = useRef<Set<string>>(new Set());
  const highestSeenLogIdRef = useRef<number>(0);
  const connectedBaselineReceivedRef = useRef<boolean>(false);

  // SSE event source ref
  const eventSourceRef = useRef<EventSource | null>(null);
  const pollingTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttemptRef = useRef<number>(0);

  const trackAndCheckProcessed = (eventKey: string): boolean => {
    if (processedEventIdsRef.current.has(eventKey)) {
      return false;
    }
    if (processedEventIdsRef.current.size >= 2000) {
      // Evict only the oldest 500 keys so recent deduplication remains intact
      let evicted = 0;
      for (const k of processedEventIdsRef.current) {
        processedEventIdsRef.current.delete(k);
        evicted += 1;
        if (evicted >= 500) break;
      }
    }
    processedEventIdsRef.current.add(eventKey);
    return true;
  };

  const processIncomingEvent = useCallback((event: { type: string; data?: any; timestamp?: string; latestAuditId?: number }) => {
    setLastServerTime(event.timestamp || new Date().toISOString());

    if (event.type === 'CONNECTED') {
      connectedBaselineReceivedRef.current = true;
      if (typeof event.latestAuditId === 'number' && event.latestAuditId > highestSeenLogIdRef.current) {
        highestSeenLogIdRef.current = event.latestAuditId;
      }
      return;
    }

    if (event.type === 'NEW_INVOCATION' && event.data) {
      const eventKey = `log_${event.data.id}`;
      if (trackAndCheckProcessed(eventKey)) {
        if (typeof event.data.id === 'number' && event.data.id > highestSeenLogIdRef.current) {
          highestSeenLogIdRef.current = event.data.id;
        }
        setStreamEventsCount((prev) => prev + 1);
        onNewLogRef.current?.(event.data);
      }
    } else if (event.type === 'THREAT_ALERT' && event.data) {
      const eventKey = `alt_${event.data.id}`;
      if (trackAndCheckProcessed(eventKey)) {
        setStreamEventsCount((prev) => prev + 1);
        onNewAlertRef.current?.(event.data);
      }
    } else if ((event.type === 'INCIDENT_CREATED' || event.type === 'INCIDENT_UPDATED') && event.data) {
      const eventKey = `inc_${event.type}_${event.data.id}_${event.timestamp || ''}`;
      if (trackAndCheckProcessed(eventKey)) {
        setStreamEventsCount((prev) => prev + 1);
        onIncidentUpdateRef.current?.(event.data);
      }
    }
  }, []);

  // Connect to SSE stream with polling fallback and automatic SSE reconnection
  useEffect(() => {
    let isCancelled = false;

    const clearPolling = () => {
      if (pollingTimerRef.current) {
        clearInterval(pollingTimerRef.current);
        pollingTimerRef.current = null;
      }
    };

    const clearReconnectTimer = () => {
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
    };

    const startPollingFallback = () => {
      if (isCancelled || pollingTimerRef.current) return;
      setConnectionStatus('POLLING_FALLBACK');

      const poll = async () => {
        try {
          const [healthRes, overviewRes] = await Promise.all([
            fetch('/api/system/health').catch(() => null),
            fetch('/api/system/overview').catch(() => null)
          ]);

          if (healthRes && healthRes.ok) {
            const data = await healthRes.json();
            if (!isCancelled) {
              setLastServerTime(data.timestamp || new Date().toISOString());
            }
          }

          if (overviewRes && overviewRes.ok && !isCancelled) {
            const ovData = await overviewRes.json();
            const logs: SecurityAuditLog[] = Array.isArray(ovData?.logs) ? ovData.logs : [];
            if (logs.length > 0) {
              const sortedAsc = [...logs].sort((a, b) => a.id - b.id);
              if (highestSeenLogIdRef.current === 0 && !connectedBaselineReceivedRef.current) {
                // Establish baseline cursor without replaying historical logs
                highestSeenLogIdRef.current = sortedAsc[sortedAsc.length - 1].id;
                connectedBaselineReceivedRef.current = true;
              } else {
                for (const item of sortedAsc) {
                  if (item.id > highestSeenLogIdRef.current) {
                    processIncomingEvent({
                      type: 'NEW_INVOCATION',
                      data: item,
                      timestamp: item.timestamp
                    });
                  }
                }
              }
            }
          }
        } catch {
          // ignore transient poll failure
        }
      };

      poll();
      pollingTimerRef.current = setInterval(poll, pollingIntervalMs);
    };

    const initEventSource = () => {
      if (isCancelled) return;
      clearReconnectTimer();

      try {
        if (eventSourceRef.current) {
          eventSourceRef.current.close();
        }
        const es = new EventSource('/api/v1/realtime/stream');
        eventSourceRef.current = es;

        es.onopen = () => {
          if (!isCancelled) {
            reconnectAttemptRef.current = 0;
            setConnectionStatus('LIVE_STREAMING');
            setReconnectAttempts(0);
            clearPolling();
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
          if (isCancelled) return;
          es.close();
          eventSourceRef.current = null;
          reconnectAttemptRef.current += 1;
          setReconnectAttempts(reconnectAttemptRef.current);
          startPollingFallback();

          const backoffMs = Math.min(30000, 3000 * Math.pow(2, Math.min(3, reconnectAttemptRef.current - 1)));
          reconnectTimerRef.current = setTimeout(() => {
            if (!isCancelled) {
              setConnectionStatus('RECONNECTING');
              initEventSource();
            }
          }, backoffMs);
        };
      } catch {
        startPollingFallback();
      }
    };

    initEventSource();

    return () => {
      isCancelled = true;
      clearReconnectTimer();
      clearPolling();
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
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
