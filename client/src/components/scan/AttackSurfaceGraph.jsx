import React, { useMemo } from 'react';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  Handle,
  Position
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Shield, Lock, Globe, AlertTriangle, AlertOctagon, CheckCircle } from 'lucide-react';

// Custom Node: API Root
const ApiRootNode = ({ data }) => (
  <div className="px-4 py-3 shadow-card rounded-xl bg-sentinel-900 border-2 border-sentinel-700 text-white min-w-[200px]">
    <Handle type="source" position={Position.Bottom} className="w-2.5 h-2.5 bg-sentinel-400" />
    <div className="flex items-center gap-2">
      <Shield className="w-5 h-5 text-sentinel-300" />
      <div>
        <h4 className="text-xs font-extrabold tracking-tight truncate max-w-[160px]">{data.label}</h4>
        <p className="text-[10px] text-sentinel-300">v{data.version || '1.0'} • {data.totalEndpoints} endpoints</p>
      </div>
    </div>
  </div>
);

// Custom Node: Auth Scheme
const AuthSchemeNode = ({ data }) => (
  <div className="px-3.5 py-2.5 shadow-subtle rounded-xl bg-white border-2 border-sentinel-300 text-ink min-w-[180px]">
    <Handle type="target" position={Position.Top} className="w-2 h-2 bg-sentinel-500" />
    <Handle type="source" position={Position.Bottom} className="w-2 h-2 bg-sentinel-500" />
    <div className="flex items-center gap-2">
      <div className="w-6 h-6 rounded-lg bg-sentinel-100 text-sentinel-800 flex items-center justify-center">
        <Lock className="w-3.5 h-3.5" />
      </div>
      <div>
        <p className="text-xs font-bold text-sentinel-900 truncate max-w-[130px]">{data.label}</p>
        <p className="text-[10px] text-ink-muted uppercase">{data.type || 'scheme'}</p>
      </div>
    </div>
  </div>
);

// Custom Node: Endpoint
const EndpointNode = ({ data }) => {
  const methodColors = {
    GET: 'bg-blue-50 text-blue-700 border-blue-200',
    POST: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    PUT: 'bg-amber-50 text-amber-700 border-amber-200',
    PATCH: 'bg-purple-50 text-purple-700 border-purple-200',
    DELETE: 'bg-red-50 text-red-700 border-red-200'
  };

  const riskBadge = {
    CRITICAL: 'bg-red-100 text-red-800 border-red-200',
    HIGH: 'bg-orange-100 text-orange-800 border-orange-200',
    MEDIUM: 'bg-amber-100 text-amber-800 border-amber-200',
    LOW: 'bg-blue-100 text-blue-800 border-blue-200',
    INFO: 'bg-zinc-100 text-zinc-700 border-zinc-200'
  };

  return (
    <div className="px-3 py-2 shadow-subtle rounded-xl bg-white border border-edge hover:border-sentinel-400 text-ink min-w-[210px] transition-all">
      <Handle type="target" position={Position.Top} className="w-2 h-2 bg-zinc-400" />
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 bg-zinc-400" />
      <div className="flex items-center justify-between gap-1.5 mb-1">
        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold font-mono border ${methodColors[data.method] || 'bg-zinc-100'}`}>
          {data.method}
        </span>
        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold font-mono border ${riskBadge[data.riskLevel] || riskBadge.INFO}`}>
          {data.riskLevel}
        </span>
      </div>
      <p className="text-xs font-mono text-ink font-semibold truncate max-w-[190px]" title={data.path}>
        {data.path}
      </p>
      {data.findingsCount > 0 && (
        <p className="text-[10px] text-red-600 font-semibold mt-1 flex items-center gap-1">
          <AlertTriangle className="w-3 h-3" />
          {data.findingsCount} risk factor{data.findingsCount > 1 ? 's' : ''}
        </p>
      )}
    </div>
  );
};

// Custom Node: Threat Finding
const RiskFindingNode = ({ data }) => {
  const isCrit = data.severity === 'CRITICAL';
  return (
    <div className={`px-3 py-2 shadow-card rounded-xl border min-w-[200px] ${
      isCrit ? 'bg-red-50/90 border-red-300 text-red-950' : 'bg-orange-50/90 border-orange-300 text-orange-950'
    }`}>
      <Handle type="target" position={Position.Top} className={`w-2 h-2 ${isCrit ? 'bg-red-600' : 'bg-orange-500'}`} />
      <div className="flex items-center gap-1.5">
        {isCrit ? <AlertOctagon className="w-3.5 h-3.5 text-red-600" /> : <AlertTriangle className="w-3.5 h-3.5 text-orange-600" />}
        <span className="text-[10px] font-mono font-bold">{data.ruleId}</span>
      </div>
      <p className="text-[11px] font-semibold leading-tight mt-1 truncate max-w-[180px]" title={data.title}>
        {data.title}
      </p>
    </div>
  );
};

export default function AttackSurfaceGraph({ graphData, onSelectNode }) {
  const nodeTypes = useMemo(() => ({
    apiRoot: ApiRootNode,
    authScheme: AuthSchemeNode,
    endpoint: EndpointNode,
    riskFinding: RiskFindingNode
  }), []);

  const initialNodes = graphData?.nodes || [];
  const initialEdges = graphData?.edges || [];

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  return (
    <div className="w-full h-[580px] bg-surface-muted border border-edge rounded-2xl overflow-hidden relative shadow-inner">
      <div className="absolute top-3 left-3 z-10 bg-white/90 backdrop-blur-md px-3 py-1.5 rounded-lg border border-edge shadow-subtle flex items-center gap-3 text-xs">
        <span className="font-semibold text-ink">Attack Surface Topology</span>
        <span className="text-ink-muted">|</span>
        <span className="flex items-center gap-1 text-[11px] text-sentinel-700">
          <span className="w-2 h-2 rounded-full bg-sentinel-700"></span>
          Interactive Graph
        </span>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.3}
        maxZoom={1.5}
        className="bg-dot-pattern"
      >
        <Controls className="!bg-white !border-edge !shadow-card !rounded-xl" />
        <MiniMap
          className="!bg-white !border-edge !rounded-xl !shadow-subtle"
          nodeColor={(node) => {
            if (node.type === 'apiRoot') return '#4C1D95';
            if (node.type === 'authScheme') return '#8B5CF6';
            if (node.type === 'riskFinding') return '#DC2626';
            return '#E4E4E7';
          }}
        />
        <Background color="#E4E4E7" gap={16} size={1} />
      </ReactFlow>
    </div>
  );
}
