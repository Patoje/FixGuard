import React, { useCallback, useMemo } from 'react';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  addEdge,
  Node,
  Edge,
  Handle,
  Position
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { ReconProfile, ArchitectureNode } from '../types';

// Custom Node styles
const nodeStyles = {
  root: { background: '#1e1e24', color: '#60a5fa', border: '1px solid #3b82f6', borderRadius: '8px', padding: '10px', fontSize: '14px', fontWeight: 'bold' },
  frontend: { background: '#18181b', color: '#a78bfa', border: '1px solid #8b5cf6', borderRadius: '8px', padding: '10px', fontSize: '12px' },
  backend: { background: '#18181b', color: '#34d399', border: '1px solid #10b981', borderRadius: '8px', padding: '10px', fontSize: '12px' },
  database: { background: '#18181b', color: '#f87171', border: '1px solid #ef4444', borderRadius: '8px', padding: '10px', fontSize: '12px' },
  external: { background: '#18181b', color: '#fbbf24', border: '1px solid #f59e0b', borderRadius: '8px', padding: '10px', fontSize: '12px' }
};

const CustomNode = ({ data }: any) => {
  return (
    <div style={nodeStyles[data.type as keyof typeof nodeStyles] || nodeStyles.root}>
      <Handle type="target" position={Position.Top} className="!bg-gray-500" />
      <div>{data.label}</div>
      <Handle type="source" position={Position.Bottom} className="!bg-gray-500" />
    </div>
  );
};

const nodeTypes = {
  custom: CustomNode,
};

// Traverse architecture tree to generate nodes and edges
const generateElements = (tree: ArchitectureNode, techStack: any[]) => {
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  
  let y = 50;
  
  // Root Node
  nodes.push({
    id: 'root',
    type: 'custom',
    position: { x: 400, y: y },
    data: { label: tree.name, type: 'root' },
  });

  if (!tree.children) return { nodes, edges };

  y += 150;
  let xOffset = 100;
  
  tree.children.forEach((child, i) => {
    const id = `node-${i}`;
    let type = 'backend';
    if (child.name.includes('Frontend')) type = 'frontend';
    else if (child.name.includes('Base de Datos')) type = 'database';
    else if (child.name.includes('Servicios') || child.name.includes('Integracion')) type = 'external';

    nodes.push({
      id: id,
      type: 'custom',
      position: { x: xOffset, y: y },
      data: { label: child.name, type },
    });

    edges.push({
      id: `e-root-${id}`,
      source: 'root',
      target: id,
      animated: true,
      style: { stroke: '#4b5563' }
    });

    xOffset += 250;

    // Third level (grandchildren)
    if (child.children) {
      let grandY = y + 150;
      let grandX = xOffset - 250 - (child.children.length * 50);
      
      child.children.forEach((grandChild, j) => {
        const grandId = `node-${i}-${j}`;
        nodes.push({
          id: grandId,
          type: 'custom',
          position: { x: grandX, y: grandY },
          data: { label: grandChild.name, type: type }, // Inherit parent type
        });

        edges.push({
          id: `e-${id}-${grandId}`,
          source: id,
          target: grandId,
          animated: false,
          style: { stroke: '#374151' }
        });
        
        grandX += 150;
      });
    }
  });

  return { nodes, edges };
};

export default function ApplicationBlueprint({ profile }: { profile: ReconProfile }) {
  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => generateElements(profile.architectureTree, profile.techStack), [profile]);
  
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  const onConnect = useCallback(
    (params: any) => setEdges((eds) => addEdge(params, eds)),
    [setEdges],
  );

  return (
    <div style={{ height: '600px', width: '100%', borderRadius: '16px', overflow: 'hidden', border: '1px solid rgba(255,255,255,0.1)' }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        nodeTypes={nodeTypes}
        fitView
        className="bg-zinc-950"
      >
        <Controls className="bg-zinc-900 border-zinc-800 fill-zinc-400" />
        <MiniMap 
          nodeColor={(n) => {
            if (n.data?.type === 'root') return '#3b82f6';
            if (n.data?.type === 'frontend') return '#8b5cf6';
            if (n.data?.type === 'database') return '#ef4444';
            if (n.data?.type === 'external') return '#f59e0b';
            return '#10b981';
          }}
          maskColor="rgba(0,0,0,0.8)"
          className="bg-zinc-900 border-zinc-800"
        />
        <Background color="#3f3f46" gap={16} />
      </ReactFlow>
    </div>
  );
}
