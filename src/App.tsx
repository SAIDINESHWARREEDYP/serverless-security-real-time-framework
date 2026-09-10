import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { Header, FeatureTabId } from './components/Header.tsx';
import { SimulationControl } from './components/SimulationControl.tsx';
import { AuditLogStream } from './components/AuditLogStream.tsx';
import { SecurityArchitectureModal } from './components/SecurityArchitectureModal.tsx';
import { CloudGuideModal } from './components/CloudGuideModal.tsx';
import { AuthModal } from './components/AuthModal.tsx';
import { ThreatSummaryCard } from './components/ThreatSummaryCard.tsx';
import { SystemHealthDashboard } from './components/SystemHealthDashboard.tsx';
import { AdminCommandCenter } from './components/AdminCommandCenter.tsx';
import { AnomalyAlertBanner } from './components/AnomalyAlertBanner.tsx';
import { GuestPortal } from './components/GuestPortal.tsx';
import { ZeroTrustLoginGateway } from './components/ZeroTrustLoginGateway.tsx';
import { AccessRestrictedCard } from './components/AccessRestrictedCard.tsx';
import {
  User,
  FunctionRule,
  SecurityAuditLog,
  TerminalLogEntry,
  SystemOverview,
  AuthSession,
  SecurityPolicyConfig,
  AnomalyAlert
} from './types.ts';
import {
  ShieldCheck,
  UserCheck,
  UserPlus,
  Key,
  Database,
  Plus,
  Trash2,
  Lock,
  ArrowRight,
  Shield,
  Layers,
  Sparkles,
  Cloud,
  ExternalLink
} from 'lucide-react';

export default function App() {
  const [users, setUsers] = useState<User[]>([
    { id: 'usr_secops_admin', username: 'secops_admin', password_hash: 'ZeroTrust_2026', role: 'Admin', base_risk_score: 0 },
    { id: 'usr_cloud_dev', username: 'cloud_dev', password_hash: 'ZeroTrust_2026', role: 'Developer', base_risk_score: 15 },
    { id: 'usr_auditor_guest', username: 'auditor_guest', password_hash: 'ZeroTrust_2026', role: 'Guest', base_risk_score: 30 },
    { id: 'usr_threat_actor', username: 'threat_actor', password_hash: 'ZeroTrust_2026', role: 'Guest', base_risk_score: 70 }
  ]);

  const [rules, setRules] = useState<FunctionRule[]>([
    { id: 1, current_function: 'login', allowed_next_function: 'getDashboardMetrics' },
    { id: 2, current_function: 'getDashboardMetrics', allowed_next_function: 'viewSecurityLogs' },
    { id: 3, current_function: 'viewSecurityLogs', allowed_next_function: 'deployWorkerCode' },
    { id: 4, current_function: 'deployWorkerCode', allowed_next_function: 'updateSystemPolicy' },
    { id: 5, current_function: 'viewSecurityLogs', allowed_next_function: 'rotateEncryptionKeys' },
    { id: 6, current_function: 'rotateEncryptionKeys', allowed_next_function: 'purgeColdStorageBackups' }
  ]);

  const [logs, setLogs] = useState<SecurityAuditLog[]>([]);
  const [selectedUser, setSelectedUser] = useState<string>('secops_admin');
  const [selectedRoute, setSelectedRoute] = useState<string>('getDashboardMetrics');
  const [isFiring, setIsFiring] = useState<boolean>(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isResetting, setIsResetting] = useState<boolean>(false);
  const [isDbModalOpen, setIsDbModalOpen] = useState<boolean>(false);
  const [isCloudGuideOpen, setIsCloudGuideOpen] = useState<boolean>(false);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState<boolean>(false);
  const [terminalLogs, setTerminalLogs] = useState<TerminalLogEntry[]>([]);

  // Navigation: Active Feature Tab
  const [activeTab, setActiveTab] = useState<FeatureTabId>('health');

  // Authenticated session state
  const [currentSession, setCurrentSession] = useState<AuthSession | null>({
    user: { id: 'usr_secops_admin', username: 'secops_admin', password_hash: 'ZeroTrust_2026', role: 'Admin', base_risk_score: 0 },
    token: 'zt_jwt_secops_admin_k7x9',
    loginTime: 'System Initialization',
    expiresInSeconds: 3600
  });

  // Dynamic policy configuration
  const [policyConfig, setPolicyConfig] = useState<SecurityPolicyConfig>({
    maxRiskThreshold: 75,
    sequenceViolationPenalty: 40,
    enforceStrictSequence: true
  });

  // IAM inline form state for real-time any user
  const [inlineUsername, setInlineUsername] = useState('');
  const [inlineRole, setInlineRole] = useState<'Admin' | 'Developer' | 'Guest'>('Developer');
  const [inlineRisk, setInlineRisk] = useState<number>(20);
  const [inlineLoading, setInlineLoading] = useState(false);
  const [inlineMsg, setInlineMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Architecture inline new rule state
  const [newRuleCurrent, setNewRuleCurrent] = useState('login');
  const [newRuleNext, setNewRuleNext] = useState('getDashboardMetrics');

  // Network connectivity status
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'syncing' | 'reconnecting'>('syncing');

  // Real-time Anomaly Alert State
  const [acknowledgedAlertIds, setAcknowledgedAlertIds] = useState<Set<string>>(new Set());

  // Derive active anomalies dynamically from audit logs & users
  const anomalyAlerts = useMemo<AnomalyAlert[]>(() => {
    const alerts: AnomalyAlert[] = [];
    const seen = new Set<string>();

    // 1. Scan blocked logs for high-risk / Markov / RBAC anomalies
    for (const log of logs) {
      if (log.status === 'BLOCKED') {
        const key = `${log.username}-${log.requested_function}-${log.timestamp}`;
        if (!seen.has(key)) {
          seen.add(key);

          const isRbac = log.reason.includes('RBAC Breach') || log.reason.includes('Unauthorized role');
          const isSequence = log.reason.includes('Abnormal invocation order') || log.reason.includes('sequence');
          const isCriticalRisk = log.calculated_risk >= (policyConfig?.maxRiskThreshold ?? 75);
          const isLockdown = log.reason.includes('LOCKDOWN');

          const alertType = isRbac
            ? 'PRIVILEGE_ESCALATION'
            : isSequence
            ? 'SEQUENCE_VIOLATION'
            : isCriticalRisk
            ? 'CRITICAL_RISK'
            : 'BRUTE_FORCE_ATTEMPT';

          const severity = isCriticalRisk || isLockdown ? 'CRITICAL' : isRbac ? 'HIGH' : 'MEDIUM';

          alerts.push({
            id: `alert_${log.id}`,
            timestamp: log.timestamp,
            type: alertType,
            severity,
            username: log.username,
            endpoint: log.requested_function,
            riskScore: log.calculated_risk,
            message: log.reason,
            mitigation: 'Cloudflare Edge Interceptor 403 Suspended',
            acknowledged: acknowledgedAlertIds.has(`alert_${log.id}`)
          });
        }
      }
    }

    // 2. Scan users with quarantined or abnormal base risk
    for (const user of users) {
      if (user.base_risk_score >= 80) {
        const key = `user_quarantine_${user.username}`;
        if (!seen.has(key)) {
          seen.add(key);
          alerts.push({
            id: key,
            timestamp: 'Policy Rule',
            type: 'CRITICAL_RISK',
            severity: 'CRITICAL',
            username: user.username,
            endpoint: 'Global Edge Perimeter',
            riskScore: user.base_risk_score,
            message: `Principal [${user.username}] holds critical base risk (${user.base_risk_score}%) — flagged for quarantine.`,
            mitigation: 'Administrative Quarantine Active',
            acknowledged: acknowledgedAlertIds.has(key)
          });
        }
      }
    }

    return alerts.slice(0, 10);
  }, [logs, users, policyConfig, acknowledgedAlertIds]);

  const handleAcknowledgeAlert = (id: string) => {
    setAcknowledgedAlertIds(prev => new Set(prev).add(id));
  };

  const handleQuarantineUser = async (username: string) => {
    try {
      const res = await fetch(`/api/system/users/${encodeURIComponent(username)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ base_risk_score: 100 })
      });
      if (res.ok) {
        await fetchOverview();
        addTerminalLog('alert', `[SECOPS] Principal [${username}] has been quarantined (Base Risk: 100%).`);
      }
    } catch (e: any) {
      addTerminalLog('error', `[SECOPS] Quarantine action failed: ${e?.message || String(e)}`);
    }
  };

  const addTerminalLog = useCallback((type: TerminalLogEntry['type'], text: string) => {
    setTerminalLogs((prev) => [
      ...prev,
      {
        id: Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toLocaleTimeString(),
        type,
        text
      }
    ]);
  }, []);

  // Fetch system overview safely with graceful retry handling
  const fetchOverview = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const res = await fetch('/api/system/overview', {
        headers: { Accept: 'application/json' }
      });
      if (res.ok) {
        const data: SystemOverview = await res.json();
        if (data && Array.isArray(data.users)) setUsers(data.users);
        if (data && Array.isArray(data.rules)) setRules(data.rules);
        if (data && Array.isArray(data.logs)) setLogs(data.logs);
        if (data && data.policyConfig) setPolicyConfig(data.policyConfig);
        setConnectionStatus('connected');
      } else {
        setConnectionStatus('reconnecting');
      }
    } catch {
      // Non-blocking connection retry (e.g. during server reload or brief offline pause)
      setConnectionStatus('reconnecting');
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    let isMounted = true;
    const executeFetch = async () => {
      if (!isMounted) return;
      await fetchOverview();
    };

    executeFetch();
    const interval = setInterval(executeFetch, 4000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [fetchOverview]);

  // Initial welcome logs
  useEffect(() => {
    addTerminalLog('info', '[INIT] Serverless Security Verification Framework initialized.');
    addTerminalLog('info', '[RBAC] Cloudflare Edge Interceptor rule matrices loaded.');
    addTerminalLog('success', '[READY] Security simulation and audit pipeline online.');
  }, [addTerminalLog]);

  // Update policy configuration
  const handleUpdatePolicyConfig = async (newConfig: SecurityPolicyConfig) => {
    try {
      const res = await fetch('/api/system/policy-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newConfig)
      });
      if (res.ok) {
        const data = await res.json();
        setPolicyConfig(data.policyConfig);
        addTerminalLog('success', `[POLICY] Security rule parameters updated: Max Risk Cutoff = ${data.policyConfig.maxRiskThreshold}%, Sequence Penalty = +${data.policyConfig.sequenceViolationPenalty}%`);
      }
    } catch (err: any) {
      addTerminalLog('error', `[POLICY] Failed to update parameters: ${err?.message || String(err)}`);
    }
  };

  // Execute Pipeline simulation
  const handleFirePipeline = async (user: string, route: string) => {
    setIsFiring(true);
    setTerminalLogs([]);

    addTerminalLog('info', `[INFO] Request initiated for principal [${user}] via edge security interceptor...`);

    try {
      addTerminalLog('post', `[POST] Verifying credentials and acquiring Bearer token for [${user}]...`);

      const authResponse = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: 'ZeroTrust_2026' })
      });

      const authData = await authResponse.json();

      if (!authData.success) {
        addTerminalLog('error', `[ERROR] Identity token signature rejected: ${authData.error}`);
        setIsFiring(false);
        fetchOverview();
        return;
      }

      addTerminalLog(
        'success',
        `[SUCCESS] Bearer token verified for [${authData.role}] (Base Risk: ${authData.userRisk}%). Signature: ${authData.token.substring(0, 20)}...`
      );
      addTerminalLog(
        'get',
        `[TRANSIT] Intercepting request for target serverless endpoint: /api/${route}...`
      );

      const pipelineResponse = await fetch(`/api/${route}`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${authData.token}`
        }
      });

      const pipelineData = await pipelineResponse.json();

      if (pipelineResponse.status === 200) {
        addTerminalLog('metric', `[METRIC] Security Clearance: STATUS 200 (OK - ALLOWED).`);
        addTerminalLog('success', `[RESPONSE DATA]: ${JSON.stringify(pipelineData, null, 2)}`);
      } else {
        addTerminalLog(
          'alert',
          `[ALERT] Security Firewall Intercept: STATUS ${pipelineResponse.status} (BLOCKED).`
        );
        addTerminalLog('error', `[THREAT REASON]: ${pipelineData.error}`);
        if (pipelineData.metrics) {
          addTerminalLog(
            'metric',
            `[CALCULATED TOTAL RISK]: ${pipelineData.metrics.riskScore}% (Cutoff: ${policyConfig.maxRiskThreshold}%) | Threat Signature: ${pipelineData.metrics.threatReason}`
          );
        }
      }

      await fetchOverview();
    } catch (e: any) {
      addTerminalLog(
        'error',
        `[CRITICAL EXCEPTION] Connection timed out or endpoint target unreachable. Detail: ${e?.message || String(e)}`
      );
    } finally {
      setIsFiring(false);
    }
  };

  // Reset database to initial seed
  const handleReset = async () => {
    setIsResetting(true);
    try {
      const res = await fetch('/api/system/reset', { method: 'POST' });
      if (res.ok) {
        addTerminalLog('info', `[SYSTEM] Database reset to initial baseline schema & mock data.`);
        await fetchOverview();
      } else {
        addTerminalLog('error', `[SYSTEM] Failed to reset baseline state.`);
      }
    } catch (err: any) {
      addTerminalLog('error', `[SYSTEM] Reset operation failed: ${err?.message || String(err)}`);
    } finally {
      setIsResetting(false);
    }
  };

  // Clear audit logs
  const handleClearLogs = async () => {
    try {
      const res = await fetch('/api/system/clearLogs', { method: 'POST' });
      if (res.ok) {
        setLogs([]);
        addTerminalLog('info', `[SYSTEM] Audit logs cleared.`);
      } else {
        addTerminalLog('error', `[SYSTEM] Failed to clear audit ledger.`);
      }
    } catch (err: any) {
      addTerminalLog('error', `[SYSTEM] Clear logs operation failed: ${err?.message || String(err)}`);
    }
  };

  // Add rule
  const handleAddRule = async (current: string, next: string) => {
    try {
      const res = await fetch('/api/system/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_function: current, allowed_next_function: next })
      });
      if (res.ok) {
        await fetchOverview();
        addTerminalLog('success', `[SYSTEM] Added sequential execution rule: ${current} -> ${next}`);
      } else {
        addTerminalLog('error', `[SYSTEM] Failed to add sequential rule.`);
      }
    } catch (err: any) {
      addTerminalLog('error', `[SYSTEM] Add rule failed: ${err?.message || String(err)}`);
    }
  };

  // Delete rule
  const handleDeleteRule = async (id: number) => {
    try {
      const res = await fetch(`/api/system/rules/${id}`, { method: 'DELETE' });
      if (res.ok) {
        await fetchOverview();
        addTerminalLog('info', `[SYSTEM] Rule ID #${id} removed from architectural policy.`);
      } else {
        addTerminalLog('error', `[SYSTEM] Failed to remove rule #${id}.`);
      }
    } catch (err: any) {
      addTerminalLog('error', `[SYSTEM] Rule removal failed: ${err?.message || String(err)}`);
    }
  };

  // Inline Real-Time Dynamic User Registration & Login
  const handleInlineRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inlineUsername.trim()) return;
    setInlineLoading(true);
    setInlineMsg(null);

    try {
      const clean = inlineUsername.trim().toLowerCase().replace(/\s+/g, '_');
      const res = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: clean,
          password: 'ZeroTrust_2026',
          role: inlineRole,
          base_risk_score: Number(inlineRisk)
        })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        const newUser: User = {
          id: data.user?.id || `usr_${clean}`,
          username: clean,
          password_hash: 'ZeroTrust_2026',
          role: inlineRole,
          base_risk_score: Number(inlineRisk)
        };

        const newSession: AuthSession = {
          user: newUser,
          token: data.token || `zt_jwt_${clean}_${Date.now().toString(36)}`,
          loginTime: new Date().toLocaleTimeString(),
          expiresInSeconds: 3600
        };

        setCurrentSession(newSession);
        setSelectedUser(clean);
        setUsers(prev => {
          if (prev.some(u => u.username === clean)) return prev;
          return [...prev, newUser];
        });

        setInlineMsg({ type: 'success', text: `Identity [${clean}] provisioned and activated in real-time!` });
        setInlineUsername('');
        addTerminalLog('success', `[IAM] Real-time user [${clean}] (${inlineRole}) provisioned with base risk ${inlineRisk}%.`);
      } else {
        setInlineMsg({ type: 'error', text: data.error || 'Failed to register identity.' });
      }
    } catch (err: any) {
      setInlineMsg({ type: 'error', text: err?.message || 'Registration failed.' });
    } finally {
      setInlineLoading(false);
    }
  };

  const handleQuickSwitchUser = async (targetUser: User) => {
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: targetUser.username, password: 'ZeroTrust_2026' })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        const session: AuthSession = {
          user: targetUser,
          token: data.token || `zt_jwt_${targetUser.username}_${Date.now().toString(36)}`,
          loginTime: new Date().toLocaleTimeString(),
          expiresInSeconds: 3600
        };
        setCurrentSession(session);
        setSelectedUser(targetUser.username);
        addTerminalLog('info', `[IAM] Active session switched to: ${targetUser.username} (${targetUser.role})`);

        // Automatically guide the user to their role-appropriate tab if current tab is forbidden
        if (targetUser.role === 'Guest' && (activeTab === 'admin' || activeTab === 'iam' || activeTab === 'architecture' || activeTab === 'overview' || activeTab === 'interceptor')) {
          setActiveTab('guest');
        } else if (targetUser.role === 'Developer' && (activeTab === 'admin' || activeTab === 'iam' || activeTab === 'overview' || activeTab === 'guest')) {
          setActiveTab('interceptor');
        } else if (targetUser.role === 'Admin' && activeTab === 'guest') {
          setActiveTab('admin');
        }
      } else {
        addTerminalLog('error', `[IAM] Failed to authenticate principal: ${data?.error || 'Unknown error'}`);
      }
    } catch (e: any) {
      addTerminalLog('error', `[IAM] Quick switch failed: ${e?.message || String(e)}`);
    }
  };

  const handleQuickSwitchRole = async (targetRole: 'Admin' | 'Developer' | 'Guest') => {
    let candidate = users.find(u => u.role === targetRole);
    if (!candidate) {
      if (targetRole === 'Guest') {
        candidate = { id: 'usr_alice_guest', username: 'alice_guest', password_hash: 'ZeroTrust_2026', role: 'Guest', base_risk_score: 20 };
      } else if (targetRole === 'Developer') {
        candidate = { id: 'usr_bob_developer', username: 'bob_developer', password_hash: 'ZeroTrust_2026', role: 'Developer', base_risk_score: 10 };
      } else {
        candidate = { id: 'usr_secops_admin', username: 'secops_admin', password_hash: 'ZeroTrust_2026', role: 'Admin', base_risk_score: 0 };
      }
      setUsers(prev => [...prev, candidate!]);
    }
    await handleQuickSwitchUser(candidate);
    if (targetRole === 'Guest') {
      setActiveTab('guest');
    } else if (targetRole === 'Developer') {
      setActiveTab('interceptor');
    } else {
      setActiveTab('admin');
    }
  };

  const handleLogout = () => {
    setCurrentSession(null);
    addTerminalLog('alert', '[IAM GATEWAY] Principal signed out. All role-gated interfaces locked.');
  };

  const handleGatewayLogin = (session: AuthSession, isNewUser?: boolean) => {
    setCurrentSession(session);
    setSelectedUser(session.user.username);
    if (isNewUser) {
      setUsers(prev => {
        if (prev.some(u => u.username === session.user.username)) return prev;
        return [...prev, session.user];
      });
    }
    if (session.user.role === 'Guest') {
      setActiveTab('guest');
    } else if (session.user.role === 'Developer') {
      setActiveTab('interceptor');
    } else {
      setActiveTab('admin');
    }
    addTerminalLog('success', `[IAM GATEWAY] Authenticated as ${session.user.username} with role '${session.user.role}'.`);
  };

  const handleDirectInvokeFromAdmin = async (endpoint: string) => {
    const cleanRoute = endpoint.replace('/api/', '');
    const userToInvoke = currentSession?.user?.username || 'secops_admin';
    await handleFirePipeline(userToInvoke, cleanRoute);
  };

  const blockedCount = logs.filter(l => l.status === 'BLOCKED').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-4 sm:p-6 lg:p-8 font-sans selection:bg-blue-600/30 selection:text-white">
      <div className="max-w-[1440px] mx-auto">
        {/* Navigation & Header with Dynamic Feature Line Navigation */}
        <Header
          onReset={handleReset}
          onClearLogs={handleClearLogs}
          isResetting={isResetting}
          onOpenDbModal={() => setIsDbModalOpen(true)}
          onOpenCloudGuide={() => setIsCloudGuideOpen(true)}
          currentSession={currentSession}
          onOpenAuthModal={() => setIsAuthModalOpen(true)}
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          logsCount={logs.length}
          usersCount={users.length}
          blockedCount={blockedCount}
          connectionStatus={connectionStatus}
          onQuickSwitchRole={handleQuickSwitchRole}
          onLogout={handleLogout}
        />

        {/* If no active session, show the Zero-Trust Login Gateway */}
        {!currentSession ? (
          <div className="py-4">
            <ZeroTrustLoginGateway
              users={users}
              onLoginSuccess={handleGatewayLogin}
              onAddTerminalLog={addTerminalLog}
            />
          </div>
        ) : (
          <>
            {/* Real-time Security Anomaly Alert Banner (Admin & Developer) */}
            {currentSession.user.role !== 'Guest' && (
              <AnomalyAlertBanner
                alerts={anomalyAlerts}
                onAcknowledgeAlert={handleAcknowledgeAlert}
                onQuarantineUser={handleQuarantineUser}
                onNavigateToAudit={() => setActiveTab('audit')}
                onNavigateToAdmin={() => setActiveTab('admin')}
              />
            )}

            {/* FEATURE VIEW 0: EXECUTIVE ADMIN COMMAND & SECOPS CENTER */}
            {activeTab === 'admin' && (
              currentSession.user.role === 'Admin' ? (
                <AdminCommandCenter
                  users={users}
                  logs={logs}
                  rules={rules}
                  policyConfig={policyConfig}
                  currentSession={currentSession}
                  onSwitchSession={handleQuickSwitchUser}
                  onUpdatePolicyConfig={handleUpdatePolicyConfig}
                  onResetDatabase={handleReset}
                  onClearLogs={handleClearLogs}
                  onRefreshData={fetchOverview}
                  onAddTerminalLog={addTerminalLog}
                  onDirectInvoke={handleDirectInvokeFromAdmin}
                  isResetting={isResetting}
                />
              ) : (
                <AccessRestrictedCard
                  requiredRole="Admin"
                  currentSession={currentSession}
                  onNavigateToPermitted={() => setActiveTab(currentSession.user.role === 'Developer' ? 'interceptor' : 'guest')}
                  onSwitchToAdmin={() => handleQuickSwitchRole('Admin')}
                />
              )
            )}

            {/* FEATURE VIEW: RESTRICTED GUEST WORKSPACE */}
            {activeTab === 'guest' && (
              <GuestPortal
                currentSession={currentSession}
                logs={logs}
                onFireFunction={handleDirectInvokeFromAdmin}
                isFiring={isFiring}
              />
            )}

            {/* FEATURE VIEW 1: HEALTH & RISK ANALYTICS */}
            {activeTab === 'health' && (
              <div className="space-y-6">
                <ThreatSummaryCard logs={logs} />
                <SystemHealthDashboard
                  users={users}
                  logs={logs}
                  policyConfig={policyConfig}
                />
              </div>
            )}

            {/* FEATURE VIEW 2: SECURITY INTERCEPTOR & SIMULATOR */}
            {activeTab === 'interceptor' && (
              currentSession.user.role === 'Guest' ? (
                <AccessRestrictedCard
                  requiredRole="Developer"
                  currentSession={currentSession}
                  onNavigateToPermitted={() => setActiveTab('guest')}
                  onSwitchToAdmin={() => handleQuickSwitchRole('Admin')}
                />
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                  <div className="lg:col-span-5 xl:col-span-5">
                    <SimulationControl
                      users={users}
                      selectedUser={selectedUser}
                      onSelectUser={setSelectedUser}
                      selectedRoute={selectedRoute}
                      onSelectRoute={setSelectedRoute}
                      onFire={handleFirePipeline}
                      isFiring={isFiring}
                      terminalLogs={terminalLogs}
                      onClearTerminal={() => setTerminalLogs([])}
                      currentSession={currentSession}
                      policyConfig={policyConfig}
                      onUpdatePolicyConfig={handleUpdatePolicyConfig}
                    />
                  </div>

                  <div className="lg:col-span-7 xl:col-span-7 space-y-4">
                    {/* Interceptor Policy Guide Card */}
                    <div className="bg-slate-900/90 border border-slate-800 p-5 rounded-xl font-mono text-xs">
                      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
                        <div className="flex items-center gap-2 text-white font-bold text-sm">
                          <Shield className="w-4 h-4 text-blue-400" />
                          Runtime Interception Architecture
                        </div>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                          Live Enforcement
                        </span>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
                        <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                          <div className="text-slate-400 text-[10px] uppercase font-bold">1. RBAC Guard</div>
                          <div className="text-white font-semibold mt-1">Role Validation</div>
                          <div className="text-[11px] text-slate-400 mt-1">Admin, Developer, Guest clearances checked before function invocation.</div>
                        </div>

                        <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                          <div className="text-slate-400 text-[10px] uppercase font-bold">2. Markov Sequence</div>
                          <div className="text-white font-semibold mt-1">Order Validation</div>
                          <div className="text-[11px] text-slate-400 mt-1">Out-of-order jumps incur a +{policyConfig.sequenceViolationPenalty}% threat penalty.</div>
                        </div>

                        <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg">
                          <div className="text-slate-400 text-[10px] uppercase font-bold">3. Cutoff Firewall</div>
                          <div className="text-white font-semibold mt-1">Risk Threshold</div>
                          <div className="text-[11px] text-slate-400 mt-1">Requests exceeding {policyConfig.maxRiskThreshold}% risk are immediately blocked.</div>
                        </div>
                      </div>

                      {/* Quick Fire Presets */}
                      <div className="p-3 bg-blue-950/20 border border-blue-500/30 rounded-lg text-blue-300">
                        <div className="font-semibold text-white mb-1 flex items-center gap-2">
                          <Sparkles className="w-3.5 h-3.5 text-blue-400" />
                          Simulation Tip:
                        </div>
                        Use the 1-Click Test Scenarios in the left panel to instantly demonstrate legitimate admin flows, privilege escalation attempts, sequence anomalies, and high-risk exploits!
                      </div>
                    </div>

                    {/* Compact Audit Log Stream Preview */}
                    <AuditLogStream
                      logs={logs}
                      onRefresh={fetchOverview}
                      isRefreshing={isRefreshing}
                    />
                  </div>
                </div>
              )
            )}

            {/* FEATURE VIEW 3: AUDIT LEDGER */}
            {activeTab === 'audit' && (
              <div className="space-y-4">
                <AuditLogStream
                  logs={logs}
                  onRefresh={fetchOverview}
                  isRefreshing={isRefreshing}
                />
              </div>
            )}

            {/* FEATURE VIEW 4: IAM & REAL-TIME USER ACCESS (ADMIN ONLY) */}
            {activeTab === 'iam' && (
              currentSession.user.role !== 'Admin' ? (
                <AccessRestrictedCard
                  requiredRole="Admin"
                  currentSession={currentSession}
                  onNavigateToPermitted={() => setActiveTab(currentSession.user.role === 'Developer' ? 'interceptor' : 'guest')}
                  onSwitchToAdmin={() => handleQuickSwitchRole('Admin')}
                />
              ) : (
                <div className="space-y-6 font-mono">
                  {/* Real-Time Any User Provisioning Card */}
                  <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-lg">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4 mb-5">
                      <div>
                        <h3 className="text-base font-bold text-white flex items-center gap-2">
                          <UserPlus className="w-5 h-5 text-emerald-400" />
                          Real-Time Any User Onboarding &amp; Sign In
                        </h3>
                        <p className="text-xs text-slate-400 mt-1">
                          Anyone can enter their username in real-time. The server dynamically creates the user with your chosen role and base risk!
                        </p>
                      </div>
                      <span className="text-[10px] px-2.5 py-1 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 uppercase font-semibold">
                        Zero-Trust Dynamic IAM
                      </span>
                    </div>

                    {inlineMsg && (
                      <div className={`p-3 rounded-lg text-xs mb-4 flex items-center gap-2 ${
                        inlineMsg.type === 'success'
                          ? 'bg-emerald-950/60 border border-emerald-500/40 text-emerald-200'
                          : 'bg-rose-950/60 border border-rose-500/40 text-rose-200'
                      }`}>
                        <Sparkles className="w-4 h-4 shrink-0" />
                        <span>{inlineMsg.text}</span>
                      </div>
                    )}

                    <form onSubmit={handleInlineRegister} className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                          <label className="block text-xs font-semibold text-slate-300 mb-1 uppercase tracking-wider">
                            Identity Handle / Username
                          </label>
                          <input
                            type="text"
                            value={inlineUsername}
                            onChange={(e) => setInlineUsername(e.target.value)}
                            placeholder="e.g. your_name, sec_auditor"
                            className="w-full p-2.5 bg-slate-950 border border-slate-800 text-white text-xs rounded-lg focus:outline-none focus:border-blue-500 font-mono"
                            required
                          />
                        </div>

                        <div>
                          <label className="block text-xs font-semibold text-slate-300 mb-1 uppercase tracking-wider">
                            Assigned RBAC Role
                          </label>
                          <select
                            value={inlineRole}
                            onChange={(e) => setInlineRole(e.target.value as any)}
                            className="w-full p-2.5 bg-slate-950 border border-slate-800 text-white text-xs rounded-lg focus:outline-none focus:border-blue-500 font-mono"
                          >
                            <option value="Admin">Admin (Unrestricted Tier 3)</option>
                            <option value="Developer">Developer (Deploy & Logs Tier 2)</option>
                            <option value="Guest">Guest (Read-Only Tier 1)</option>
                          </select>
                        </div>

                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider">
                              Base Risk Score: <span className="text-white font-bold">{inlineRisk}%</span>
                            </label>
                          </div>
                          <input
                            type="range"
                            min="0"
                            max="100"
                            value={inlineRisk}
                            onChange={(e) => setInlineRisk(Number(e.target.value))}
                            className="w-full mt-2 accent-blue-500 cursor-pointer"
                          />
                        </div>
                      </div>

                      <div className="pt-2 flex items-center justify-between">
                        <div className="text-[11px] text-slate-500">
                          Auto-provisions password <code className="text-slate-300">ZeroTrust_2026</code>. Instantly usable in simulator and audit logs.
                        </div>
                        <button
                          type="submit"
                          disabled={inlineLoading}
                          className="px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-2 transition-all shadow-md shadow-emerald-600/20 disabled:opacity-50"
                        >
                          <UserPlus className="w-4 h-4" />
                          {inlineLoading ? 'Provisioning...' : 'Provision & Sign In In Real Time'}
                        </button>
                      </div>
                    </form>
                  </div>

                  {/* Active User Roster Cards */}
                  <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl shadow-lg">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <UserCheck className="w-4 h-4 text-blue-400" />
                        Active Principals Roster ({users.length})
                      </h3>
                      <span className="text-xs text-slate-400">
                        Click any principal to activate their live session
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                      {users.map((u) => {
                        const isCurrent = currentSession?.user.username === u.username;
                        const isUntrusted = u.base_risk_score >= 70;
                        return (
                          <div
                            key={u.id}
                            className={`p-4 rounded-xl border transition-all flex flex-col justify-between ${
                              isCurrent
                                ? 'bg-blue-950/40 border-blue-500 ring-1 ring-blue-500/50'
                                : isUntrusted
                                ? 'bg-rose-950/20 border-rose-900/60 hover:border-rose-700/80'
                                : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                            }`}
                          >
                            <div>
                              <div className="flex items-start justify-between mb-2">
                                <div className="text-xs font-bold text-white truncate max-w-[150px]">
                                  {u.username}
                                </div>
                                {isCurrent && (
                                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                                    Active
                                  </span>
                                )}
                              </div>

                              <div className="space-y-1 text-[11px] text-slate-400">
                                <div>Role: <span className="text-slate-200 font-semibold">{u.role}</span></div>
                                <div>
                                  Base Risk:{' '}
                                  <span className={`font-bold ${
                                    u.base_risk_score >= 70 ? 'text-rose-400' :
                                    u.base_risk_score > 20 ? 'text-amber-400' :
                                    'text-emerald-400'
                                  }`}>
                                    {u.base_risk_score}%
                                  </span>
                                </div>
                              </div>
                            </div>

                            <button
                              type="button"
                              onClick={() => handleQuickSwitchUser(u)}
                              className={`mt-4 w-full py-1.5 px-3 rounded-lg text-xs font-semibold transition-all border ${
                                isCurrent
                                  ? 'bg-blue-600 text-white border-blue-500'
                                  : 'bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border-slate-800'
                              }`}
                            >
                              {isCurrent ? 'Current Identity' : 'Switch To User'}
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )
            )}

            {/* FEATURE VIEW 5: CLOUD ARCHITECTURE & D1 SCHEMA */}
            {activeTab === 'architecture' && (
              currentSession.user.role === 'Guest' ? (
                <AccessRestrictedCard
                  requiredRole="Developer"
                  currentSession={currentSession}
                  onNavigateToPermitted={() => setActiveTab('guest')}
                  onSwitchToAdmin={() => handleQuickSwitchRole('Admin')}
                />
              ) : (
                <div className="space-y-6 font-mono text-xs">
                  {/* Visual Multi-Layer Pipeline Flowchart */}
                  <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-5">
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <Layers className="w-4 h-4 text-blue-400" />
                        Edge Verification Pipeline Architecture
                      </h3>
                      <div className="flex items-center gap-2">
                        {currentSession.user.role !== 'Admin' && (
                          <span className="text-[10px] px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                            Developer Review Mode
                          </span>
                        )}
                        <span className="text-[10px] text-slate-400">Cloudflare Worker + D1 SQL</span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-center">
                      <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg">
                        <div className="text-[10px] uppercase font-bold text-slate-500">Step 1</div>
                        <div className="text-white font-bold mt-1 text-sm">Client Request</div>
                        <div className="text-[11px] text-slate-400 mt-2">HTTP Bearer JWT Token passed in Authorization header</div>
                      </div>

                      <div className="p-4 bg-slate-950 border border-blue-500/40 rounded-lg">
                        <div className="text-[10px] uppercase font-bold text-blue-400">Step 2</div>
                        <div className="text-blue-300 font-bold mt-1 text-sm">Edge Interceptor</div>
                        <div className="text-[11px] text-slate-400 mt-2">RBAC evaluation + Markov sequence transition validation</div>
                      </div>

                      <div className="p-4 bg-slate-950 border border-amber-500/40 rounded-lg">
                        <div className="text-[10px] uppercase font-bold text-amber-400">Step 3</div>
                        <div className="text-amber-300 font-bold mt-1 text-sm">Risk Scorer</div>
                        <div className="text-[11px] text-slate-400 mt-2">R_final = min(100, Base + Violations). Firewall cut-off: 75%</div>
                      </div>

                      <div className="p-4 bg-slate-950 border border-emerald-500/40 rounded-lg">
                        <div className="text-[10px] uppercase font-bold text-emerald-400">Step 4</div>
                        <div className="text-emerald-300 font-bold mt-1 text-sm">Audit Commit</div>
                        <div className="text-[11px] text-slate-400 mt-2">Verdict recorded in Cloudflare D1 distributed SQLite table</div>
                      </div>
                    </div>
                  </div>

                  {/* D1 Transition Rules Manager */}
                  <div className="bg-slate-900 border border-slate-800 p-6 rounded-xl">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
                      <div>
                        <h3 className="text-sm font-bold text-white flex items-center gap-2">
                          <Database className="w-4 h-4 text-blue-400" />
                          Sequential Markov Transition Rules Matrix ({rules.length})
                        </h3>
                        <p className="text-[11px] text-slate-400 mt-0.5">
                          Defines allowed sequential invocation transitions. Non-whitelisted sequences trigger a +{policyConfig.sequenceViolationPenalty}% penalty.
                        </p>
                      </div>
                      {currentSession.user.role !== 'Admin' && (
                        <span className="text-[10px] px-2 py-1 rounded bg-slate-800 text-slate-400 border border-slate-700">
                          Read-Only (Admin Managed)
                        </span>
                      )}
                    </div>

                    {/* Add Rule Form - Admin Only */}
                    {currentSession.user.role === 'Admin' && (
                      <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg mb-4 flex flex-col sm:flex-row items-center gap-3">
                        <div className="flex-1 w-full">
                          <label className="block text-[10px] text-slate-400 uppercase font-bold mb-1">Current Function</label>
                          <input
                            type="text"
                            value={newRuleCurrent}
                            onChange={(e) => setNewRuleCurrent(e.target.value)}
                            className="w-full p-2 bg-slate-900 border border-slate-800 text-white rounded text-xs"
                            placeholder="e.g. login, getDashboardMetrics"
                          />
                        </div>
                        <ArrowRight className="w-4 h-4 text-slate-500 shrink-0 hidden sm:block mt-4" />
                        <div className="flex-1 w-full">
                          <label className="block text-[10px] text-slate-400 uppercase font-bold mb-1">Allowed Next Function</label>
                          <input
                            type="text"
                            value={newRuleNext}
                            onChange={(e) => setNewRuleNext(e.target.value)}
                            className="w-full p-2 bg-slate-900 border border-slate-800 text-white rounded text-xs"
                            placeholder="e.g. viewSecurityLogs, deployWorkerCode"
                          />
                        </div>
                        <button
                          type="button"
                          onClick={() => handleAddRule(newRuleCurrent, newRuleNext)}
                          className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded text-xs whitespace-nowrap flex items-center gap-1.5"
                        >
                          <Plus className="w-3.5 h-3.5" />
                          Add Transition Rule
                        </button>
                      </div>
                    )}

                    {/* Rules List */}
                    <div className="divide-y divide-slate-800">
                      {rules.map((rule) => (
                        <div key={rule.id} className="py-2.5 flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <span className="text-slate-500 font-mono text-[11px]">#{rule.id}</span>
                            <code className="text-blue-400 bg-blue-950/40 px-2 py-0.5 rounded border border-blue-500/20">{rule.current_function}</code>
                            <ArrowRight className="w-3.5 h-3.5 text-slate-600" />
                            <code className="text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-500/20">{rule.allowed_next_function}</code>
                          </div>
                          {currentSession.user.role === 'Admin' && (
                            <button
                              type="button"
                              onClick={() => handleDeleteRule(rule.id)}
                              className="p-1 text-slate-500 hover:text-rose-400 transition-colors"
                              title="Delete rule"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )
            )}

            {/* FEATURE VIEW 6: CONSOLIDATED CONSOLE (ALL MODULES - ADMIN ONLY) */}
            {activeTab === 'overview' && (
              currentSession.user.role !== 'Admin' ? (
                <AccessRestrictedCard
                  requiredRole="Admin"
                  currentSession={currentSession}
                  onNavigateToPermitted={() => setActiveTab(currentSession.user.role === 'Developer' ? 'interceptor' : 'guest')}
                  onSwitchToAdmin={() => handleQuickSwitchRole('Admin')}
                />
              ) : (
                <div className="space-y-6">
                  <ThreatSummaryCard logs={logs} />

                  <SystemHealthDashboard
                    users={users}
                    logs={logs}
                    policyConfig={policyConfig}
                  />

                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                    <div className="lg:col-span-5 xl:col-span-4">
                      <SimulationControl
                        users={users}
                        selectedUser={selectedUser}
                        onSelectUser={setSelectedUser}
                        selectedRoute={selectedRoute}
                        onSelectRoute={setSelectedRoute}
                        onFire={handleFirePipeline}
                        isFiring={isFiring}
                        terminalLogs={terminalLogs}
                        onClearTerminal={() => setTerminalLogs([])}
                        currentSession={currentSession}
                        policyConfig={policyConfig}
                        onUpdatePolicyConfig={handleUpdatePolicyConfig}
                      />
                    </div>

                    <div className="lg:col-span-7 xl:col-span-8">
                      <AuditLogStream
                        logs={logs}
                        onRefresh={fetchOverview}
                        isRefreshing={isRefreshing}
                      />
                    </div>
                  </div>
                </div>
              )
            )}
          </>
        )}

        {/* Professional Footer */}
        <footer className="mt-8 pt-4 border-t border-slate-800/80 text-center text-xs text-slate-500 font-mono flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            Serverless Security Verification Framework • Enterprise Zero-Trust Edition
          </div>
          <div className="flex items-center gap-4">
            <span className="text-emerald-400 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              {users.length} Active Principals
            </span>
            <span className="text-blue-400">Edge Interceptor Active</span>
          </div>
        </footer>
      </div>

      {/* Modals */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        users={users}
        currentSession={currentSession}
        onLoginSuccess={(session, isNewUser) => {
          setCurrentSession(session);
          setSelectedUser(session.user.username);
          if (isNewUser) {
            setUsers(prev => {
              if (prev.some(u => u.username === session.user.username)) return prev;
              return [...prev, session.user];
            });
          }
          addTerminalLog('success', `[IAM] Authenticated as ${session.user.username} (${session.user.role})`);
        }}
        onLogout={() => {
          setCurrentSession(null);
          addTerminalLog('alert', `[IAM] Active session terminated.`);
        }}
      />

      <SecurityArchitectureModal
        isOpen={isDbModalOpen}
        onClose={() => setIsDbModalOpen(false)}
        users={users}
        rules={rules}
        onAddRule={handleAddRule}
        onDeleteRule={handleDeleteRule}
      />

      <CloudGuideModal
        isOpen={isCloudGuideOpen}
        onClose={() => setIsCloudGuideOpen(false)}
      />
    </div>
  );
}
