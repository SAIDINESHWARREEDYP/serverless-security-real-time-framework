import React, { useState, useEffect } from 'react';
import { useTheme } from '../context/ThemeContext.tsx';
import {
  Shield,
  Zap,
  Lock,
  Database,
  ArrowRight,
  Cpu,
  Server,
  CheckCircle2,
  AlertOctagon,
  Activity,
  Radio,
  Play,
  Info,
  X,
  Layers,
  ChevronRight,
  Sparkles
} from 'lucide-react';

interface EdgeTopologyGraphicProps {
  blockedCount?: number;
  totalRequests?: number;
  lastInterceptedEndpoint?: string;
  isSimulating?: boolean;
  onTriggerTestPacket?: () => void;
}

interface TopologyNodeDetail {
  id: string;
  label: string;
  sub: string;
  icon: any;
  color: string;
  accentHex: string;
  bg: string;
  latency: string;
  cipher: string;
  invariant: string;
  runtimeSpec: string;
  description: string;
  specs: { [key: string]: string };
}

export const EdgeTopologyGraphic: React.FC<EdgeTopologyGraphicProps> = ({
  blockedCount = 0,
  totalRequests = 0,
  lastInterceptedEndpoint = 'getDashboardMetrics',
  isSimulating = false,
  onTriggerTestPacket
}) => {
  const { isLight } = useTheme();
  const [pulseIndex, setPulseIndex] = useState(0);
  const [selectedNode, setSelectedNode] = useState<TopologyNodeDetail | null>(null);
  const [manualPulse, setManualPulse] = useState(false);

  useEffect(() => {
    const timer = setInterval(() => {
      setPulseIndex((prev) => (prev + 1) % 4);
    }, 1800);
    return () => clearInterval(timer);
  }, []);

  const handleTriggerPulse = () => {
    setManualPulse(true);
    if (onTriggerTestPacket) {
      onTriggerTestPacket();
    }
    setTimeout(() => setManualPulse(false), 2000);
  };

  const nodes: TopologyNodeDetail[] = [
    {
      id: 'ingress',
      label: 'Edge Ingress & TLS',
      sub: 'JWT Bearer & mTLS Gateway',
      icon: Lock,
      color: isLight ? 'text-blue-600' : 'text-blue-400',
      accentHex: '#38bdf8',
      bg: isLight ? 'bg-blue-50/80 border-blue-200' : 'bg-blue-950/30 border-blue-500/30',
      latency: '0.8ms',
      cipher: 'TLS_AES_256_GCM_SHA384',
      invariant: 'INV-AUTH-01: Valid RS256 token signature',
      runtimeSpec: 'Cloudflare Worker V8 Isolate (Anycast Edge)',
      description: 'Terminates client TLS sessions at the nearest edge PoP, decrypts payload headers, and validates JWT cryptographical claims before allowing payload ingestion.',
      specs: {
        'Edge Location': 'Cluster-East Anycast (140+ PoPs)',
        'Session Handshake': 'TLS 1.3 / 0-RTT Session Resumption',
        'Authentication Tier': 'NIST SP 800-63B Level 3',
        'DDoS Scrubbing': 'Cloudflare Magic Transit Syn-Proxy'
      }
    },
    {
      id: 'markov',
      label: 'Markov Interceptor',
      sub: 'Discrete Stochastic Graph Engine',
      icon: Cpu,
      color: isLight ? 'text-purple-600' : 'text-purple-400',
      accentHex: '#a855f7',
      bg: isLight ? 'bg-purple-50/80 border-purple-200' : 'bg-purple-950/30 border-purple-500/30',
      latency: '1.2ms',
      cipher: 'SHA-256 State Transition Hash',
      invariant: 'INV-SEQ-02: Strict order matrix compliance',
      runtimeSpec: 'Sub-millisecond State Machine Engine',
      description: 'Computes conditional transition probabilities P(S_{t+1} | S_t) for requested API endpoints against the principal historical invocation graph to block lateral drift.',
      specs: {
        'Transition Model': 'First-Order Discrete Markov Chain',
        'State Space': '6 Protected Enterprise Functions',
        'Matrix Cache': 'Cloudflare KV Global Edge Replicas',
        'Out-of-Order Penalty': '+40% Drift Acceleration'
      }
    },
    {
      id: 'risk_engine',
      label: 'Zero-Trust Risk Engine',
      sub: 'Dynamic Cutoff Boundary (75%)',
      icon: Shield,
      color: isLight ? 'text-amber-600' : 'text-amber-400',
      accentHex: '#f59e0b',
      bg: isLight ? 'bg-amber-50/80 border-amber-200' : 'bg-amber-950/30 border-amber-500/30',
      latency: '1.1ms',
      cipher: 'AES-GCM Authenticated Risk Accumulator',
      invariant: 'INV-RISK-03: Score strictly below policy ceiling',
      runtimeSpec: 'Zero-Trust Decision Point (PEP)',
      description: 'Aggregates principal historical threat level, baseline credential score, and Markov drift penalties. Emits instant 403 Forbidden intercept if composite risk reaches threshold.',
      specs: {
        'Cutoff Boundary': '75% Composite Threat Score',
        'Policy Engine': 'NIST SP 800-207 Architecture',
        'Mitigation Latency': '< 2.4ms Automated Termination',
        'Audit Dispatch': 'D1 Ledger Real-time Synchronizer'
      }
    },
    {
      id: 'destination',
      label: 'Protected Serverless & D1',
      sub: 'Isolated SQLite Cluster & Workers',
      icon: Database,
      color: isLight ? 'text-emerald-600' : 'text-emerald-400',
      accentHex: '#10b981',
      bg: isLight ? 'bg-emerald-50/80 border-emerald-200' : 'bg-emerald-950/30 border-emerald-500/30',
      latency: '2.4ms',
      cipher: 'Encrypted-at-Rest SQLite D1 Replicas',
      invariant: 'INV-DATA-04: Isolated context execution',
      runtimeSpec: 'Serverless Isolated Micro-Services',
      description: 'Executes verified serverless workloads only after passing all zero-trust criteria. Writes immutable audit rows directly to the tamper-evident D1 ledger.',
      specs: {
        'Database Engine': 'Cloudflare D1 (Relational SQLite)',
        'Encryption': 'ChaCha20-Poly1305 at Rest',
        'Replication': 'Multi-Region Read Replicas',
        'Isolation': 'Micro-VM Memory Boundary'
      }
    }
  ];

  return (
    <div className={`glossy-panel rounded-2xl p-5 sm:p-6 transition-all duration-300 relative overflow-hidden font-mono ${
      isLight ? 'text-slate-800' : 'text-slate-100'
    }`}>
      {/* Top Glossy Light Gradient Sheen */}
      <div className="absolute top-0 left-0 right-0 h-28 bg-gradient-to-b from-blue-500/10 via-transparent to-transparent pointer-events-none" />

      {/* Header bar */}
      <div className={`flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 mb-5 border-b relative z-10 ${
        isLight ? 'border-slate-200' : 'border-slate-800/80'
      }`}>
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center border shadow-xs transition-transform hover:scale-105 ${
            isLight
              ? 'bg-blue-50 border-blue-200 text-blue-600 shadow-blue-500/10'
              : 'bg-blue-500/15 border-blue-500/30 text-blue-400 shadow-blue-500/20'
          }`}>
            <Activity className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="text-xs sm:text-sm font-bold tracking-wider flex items-center gap-2.5 flex-wrap">
              <span className={`uppercase ${isLight ? 'text-slate-900' : 'text-white'}`}>
                Enterprise Edge Verification Topology
              </span>
              <span className="inline-flex items-center gap-1.5 text-[10px] px-2.5 py-0.5 rounded-full font-semibold bg-emerald-500/15 text-emerald-600 dark:text-emerald-400 border border-emerald-500/30 shadow-xs">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                ACTIVE MESH • 140+ POPS
              </span>
            </div>
            <p className={`text-xs mt-0.5 ${isLight ? 'text-slate-500' : 'text-slate-400'}`}>
              Distributed Cloudflare Worker Interceptor Pipeline with Autonomous Markov Threat Mitigation
            </p>
          </div>
        </div>

        {/* Global Pipeline Counters & Live Pulse Button */}
        <div className="flex items-center gap-3 flex-wrap self-start md:self-auto">
          <div className={`flex items-center gap-3 px-3 py-1.5 rounded-xl border text-xs shadow-xs ${
            isLight ? 'bg-slate-100/80 border-slate-200' : 'bg-slate-900/80 border-slate-800'
          }`}>
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-slate-500">Evaluated:</span>
              <span className={`font-bold tabular-nums ${isLight ? 'text-slate-900' : 'text-white'}`}>
                {totalRequests}
              </span>
            </div>
            <span className="text-slate-400 dark:text-slate-700">|</span>
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-slate-500">Intercepted:</span>
              <span className="font-bold text-rose-500 tabular-nums">
                {blockedCount}
              </span>
            </div>
            <span className="text-slate-400 dark:text-slate-700">|</span>
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-slate-500">Passed:</span>
              <span className="font-bold text-emerald-500 tabular-nums">
                {Math.max(0, totalRequests - blockedCount)}
              </span>
            </div>
            <span className="text-slate-400 dark:text-slate-700">|</span>
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-slate-500">Verification Latency:</span>
              <span className="font-bold text-cyan-400 tabular-nums font-mono text-[11px]">
                ~0.4 ms
              </span>
            </div>
          </div>

          <button
            onClick={handleTriggerPulse}
            disabled={manualPulse || isSimulating}
            className={`glossy-btn flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition-all border shadow-xs ${
              manualPulse
                ? 'bg-blue-600 text-white border-blue-400 animate-pulse'
                : isLight
                ? 'bg-blue-50 hover:bg-blue-100 text-blue-700 border-blue-200'
                : 'bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border-blue-500/40'
            }`}
            title="Inject real-time test telemetry packet through all 4 verification nodes"
          >
            <Play className={`w-3.5 h-3.5 ${manualPulse ? 'animate-spin' : ''}`} />
            <span>{manualPulse ? 'Pulsing Mesh...' : 'Test Packet Pulse'}</span>
          </button>
        </div>
      </div>

      {/* Visual Pipeline Nodes Grid with Glassmorphic styling */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 relative z-10">
        {nodes.map((node, index) => {
          const Icon = node.icon;
          const isPulse = pulseIndex === index || isSimulating || manualPulse;

          return (
            <div
              key={node.id}
              onClick={() => setSelectedNode(node)}
              className={`p-4 rounded-xl border relative cursor-pointer glossy-card-hover group flex flex-col justify-between ${node.bg} ${
                isPulse
                  ? 'ring-2 ring-blue-500/70 shadow-lg shadow-blue-500/10'
                  : ''
              }`}
            >
              <div>
                {/* Node Header */}
                <div className="flex items-center justify-between mb-2.5">
                  <span className="text-[10px] font-mono uppercase tracking-wider font-bold text-slate-400 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: node.accentHex }} />
                    Node 0{index + 1}
                  </span>
                  <div className={`p-2 rounded-lg border transition-transform group-hover:scale-110 shadow-xs ${
                    isLight ? 'bg-white border-slate-200' : 'bg-slate-900 border-slate-700'
                  } ${node.color}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                </div>

                <div className={`font-bold text-xs sm:text-sm mb-1 tracking-tight ${isLight ? 'text-slate-900' : 'text-white'}`}>
                  {node.label}
                </div>
                <div className="text-[11px] text-slate-500 dark:text-slate-400 leading-snug">
                  {node.sub}
                </div>
              </div>

              {/* Node Footer Metadata */}
              <div className="mt-4 pt-3 border-t border-slate-300/40 dark:border-slate-800/80 flex items-center justify-between text-[10px] font-mono">
                <span className="text-slate-500 flex items-center gap-1">
                  <Activity className="w-3 h-3 text-blue-500" />
                  {node.latency}
                </span>
                <span className="text-blue-500 flex items-center gap-0.5 font-semibold group-hover:translate-x-0.5 transition-transform">
                  <span>Inspect</span>
                  <ChevronRight className="w-3 h-3" />
                </span>
              </div>

              {/* Connecting Desktop Flow Arrow */}
              {index < 3 && (
                <div className="hidden md:flex absolute -right-3 top-1/2 -translate-y-1/2 z-20 w-6 h-6 rounded-full bg-slate-900 border border-slate-700 text-blue-400 items-center justify-center shadow-md">
                  <ArrowRight className="w-3 h-3" />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Subtle Pipeline Telemetry Banner */}
      <div className={`mt-5 pt-3 border-t flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] ${
        isLight ? 'border-slate-200 text-slate-500' : 'border-slate-800/80 text-slate-400'
      }`}>
        <div className="flex items-center gap-2 flex-wrap">
          <span className="flex items-center gap-1.5 font-semibold text-blue-500">
            <Radio className="w-3.5 h-3.5 animate-pulse" />
            Autonomous Edge Defense:
          </span>
          <span>Zero packet bypasses the Markov sequence evaluation pipeline.</span>
        </div>
        <div className="flex items-center gap-3">
          <span>Target Cutoff: <strong>75%</strong></span>
          <span>•</span>
          <span>SLA Guarantee: <strong className="text-emerald-500">99.99%</strong></span>
        </div>
      </div>

      {/* Interactive Node Telemetry Modal */}
      {selectedNode && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-md animate-fade-in"
          onClick={() => setSelectedNode(null)}
        >
          <div
            className={`w-full max-w-lg rounded-2xl border p-6 font-mono shadow-2xl relative transition-all ${
              isLight ? 'bg-white border-slate-200 text-slate-900' : 'bg-slate-900 border-slate-700 text-slate-100'
            }`}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="flex items-start justify-between pb-4 border-b border-slate-200 dark:border-slate-800">
              <div className="flex items-center gap-3">
                <div className={`p-3 rounded-xl border ${selectedNode.bg} ${selectedNode.color}`}>
                  <selectedNode.icon className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-base font-bold tracking-tight">
                    {selectedNode.label}
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {selectedNode.sub}
                  </p>
                </div>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              >
                <X className="w-4 h-4 text-slate-400" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="py-4 space-y-4 text-xs">
              <p className="text-slate-600 dark:text-slate-300 leading-relaxed">
                {selectedNode.description}
              </p>

              <div className={`p-3.5 rounded-xl border space-y-2 ${
                isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-950 border-slate-800'
              }`}>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Runtime Engine:</span>
                  <span className="font-semibold text-blue-500">{selectedNode.runtimeSpec}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Average Node Latency:</span>
                  <span className="font-semibold text-emerald-500">{selectedNode.latency}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Cryptographic Cipher / Hash:</span>
                  <span className="font-mono text-[11px] text-amber-500 truncate max-w-[240px]" title={selectedNode.cipher}>
                    {selectedNode.cipher}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Security Invariant:</span>
                  <span className="font-mono text-[11px] text-purple-500 truncate max-w-[240px]" title={selectedNode.invariant}>
                    {selectedNode.invariant}
                  </span>
                </div>
              </div>

              {/* Technical Specifications Grid */}
              <div>
                <h4 className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">
                  Node Execution Attributes
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {Object.entries(selectedNode.specs).map(([key, val]) => (
                    <div
                      key={key}
                      className={`p-2.5 rounded-lg border ${
                        isLight ? 'bg-white border-slate-200' : 'bg-slate-800/40 border-slate-700/60'
                      }`}
                    >
                      <div className="text-[10px] text-slate-400">{key}</div>
                      <div className="font-semibold mt-0.5 text-slate-700 dark:text-slate-200 truncate">
                        {val}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedNode(null)}
                className="px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs transition-colors shadow-xs"
              >
                Close Telemetry Inspection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

