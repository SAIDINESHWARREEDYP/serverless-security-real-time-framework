/**
 * In-memory authentication token store.
 * Keeps active Bearer JWT strictly in JS runtime memory rather than persistent browser storage.
 */
let activeAuthToken: string | null = null;

export function setActiveAuthToken(token: string | null): void {
  activeAuthToken = token && token.trim() ? token.trim() : null;
}

export function getActiveAuthToken(): string | null {
  return activeAuthToken;
}

export function getAuthRequestHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = { ...extra };
  if (activeAuthToken && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${activeAuthToken}`;
  }
  return headers;
}
