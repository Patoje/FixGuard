"use client";

import { useEffect, useState, useMemo } from "react";
import { 
  ReactFlow, 
  Background, 
  Controls,
  Edge,
  Node,
  MarkerType,
  Handle,
  Position
} from "@xyflow/react";
import '@xyflow/react/dist/style.css';
import { Database, Server, Box } from "lucide-react";

interface EntityNode {
  name: string;
  type: string;
}

interface EntityRelation {
  source: string;
  target: string;
  relationType: string;
}

interface Props {
  entities: EntityNode[];
  relations: EntityRelation[];
}

const CustomNode = ({ data }: any) => {
  return (
    <div className="px-4 py-2 shadow-lg rounded-xl bg-zinc-900 border border-zinc-700 font-mono text-xs">
      <Handle type="target" position={Position.Top} className="w-2 h-2 !bg-zinc-500" />
      <div className="flex items-center gap-2">
        <Database className="w-3 h-3 text-cyan-400" />
        <span className="font-bold text-zinc-100">{data.label}</span>
      </div>
      <div className="text-zinc-500 mt-1" style={{ fontSize: '10px' }}>{data.type}</div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 !bg-zinc-500" />
    </div>
  );
};

const nodeTypes = {
  custom: CustomNode,
};

export default function EntityModelGraph({ entities, relations }: Props) {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);

  useEffect(() => {
    // Simple grid layout algorithm
    const newNodes: Node[] = entities.map((ent, i) => {
      const x = (i % 3) * 250 + 100;
      const y = Math.floor(i / 3) * 150 + 50;
      return {
        id: ent.name,
        type: 'custom',
        position: { x, y },
        data: { label: ent.name, type: ent.type },
      };
    });

    const newEdges: Edge[] = relations.map((rel, i) => ({
      id: `e-${rel.source}-${rel.target}-${i}`,
      source: rel.source,
      target: rel.target,
      animated: true,
      label: rel.relationType,
      style: { stroke: '#4b5563' },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: '#4b5563',
      },
    }));

    setNodes(newNodes);
    setEdges(newEdges);
  }, [entities, relations]);

  return (
    <div className="w-full h-full min-h-[400px] border border-zinc-800 rounded-xl overflow-hidden bg-zinc-950/50">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        className="bg-black/20"
      >
        <Background color="#27272a" gap={16} />
        <Controls className="bg-zinc-900 border-zinc-800 fill-zinc-400" />
      </ReactFlow>
    </div>
  );
}
