"use client";

import { useEffect, useState } from 'react';
import { ReactFlow, Background, Controls, MarkerType, Node, Edge } from '@xyflow/react';
import '@xyflow/react/dist/style.css';

interface Props {
  entityGraph: {
    nodes: Array<{id: string, label: string, type: string}>;
    edges: Array<{id: string, source: string, target: string, label: string}>;
  };
}

// Layout simple: colocar los nodos en círculos concéntricos o cuadrícula
function generateLayout(nodes: any[], edges: any[]) {
  const newNodes = nodes.map((node, i) => {
    // Calculo básico de posición para que no caigan todos en 0,0
    const columns = Math.ceil(Math.sqrt(nodes.length));
    const x = (i % columns) * 200 + 100;
    const y = Math.floor(i / columns) * 150 + 100;
    
    let bgColor = '#3b82f6'; // blue (rest resource)
    if (node.type === 'model') bgColor = '#f59e0b'; // amber
    if (node.type === 'graphql_type') bgColor = '#ec4899'; // pink

    return {
      id: node.id,
      position: { x, y },
      data: { label: node.label },
      style: { 
        background: bgColor, 
        color: 'white', 
        border: '1px solid rgba(255,255,255,0.2)',
        borderRadius: '8px',
        fontWeight: 'bold',
        padding: '10px'
      }
    };
  });

  const newEdges = edges.map(edge => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    label: edge.label,
    animated: true,
    style: { stroke: '#6366f1', strokeWidth: 2 },
    markerEnd: {
      type: MarkerType.ArrowClosed,
      color: '#6366f1',
    },
    labelStyle: { fill: '#9ca3af', fontWeight: 'bold' },
    labelBgStyle: { fill: 'transparent' }
  }));

  return { nodes: newNodes, edges: newEdges };
}

export default function EntityGraphViewer({ entityGraph }: Props) {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);

  useEffect(() => {
    if (entityGraph && entityGraph.nodes) {
      const { nodes: layoutNodes, edges: layoutEdges } = generateLayout(entityGraph.nodes, entityGraph.edges);
      setNodes(layoutNodes);
      setEdges(layoutEdges);
    }
  }, [entityGraph]);

  if (!entityGraph || entityGraph.nodes.length === 0) {
    return (
      <div className="w-full h-full flex flex-col items-center justify-center text-zinc-500 text-sm">
        <p className="mb-2">No se pudo reconstruir el grafo de entidades.</p>
        <p className="text-xs opacity-70">El Entity Relationship Engine no encontró suficientes patrones REST u ORMs.</p>
      </div>
    );
  }

  return (
    <div style={{ width: '100%', height: '100%' }} className="dark bg-zinc-950/50">
      <ReactFlow 
        nodes={nodes} 
        edges={edges}
        colorMode="dark"
        fitView
      >
        <Background color="#333" gap={16} />
        <Controls style={{ fill: '#fff', color: '#000' }} />
      </ReactFlow>
    </div>
  );
}
