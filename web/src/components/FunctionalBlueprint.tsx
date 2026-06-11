import React, { useMemo } from 'react';
import { ReactFlow, MiniMap, Controls, Background, useNodesState, useEdgesState } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { ReconProfile } from '../types';

interface FunctionalBlueprintProps {
  profile: ReconProfile;
}

export default function FunctionalBlueprint({ profile }: FunctionalBlueprintProps) {
  const { nodes, edges } = useMemo(() => {
    const newNodes: any[] = [];
    const newEdges: any[] = [];

    // Nodo Central
    newNodes.push({
      id: 'system',
      data: { label: 'Sistema / Aplicación' },
      position: { x: 400, y: 50 },
      style: { background: '#18181b', color: '#e4e4e7', border: '1px solid #3b82f6', borderRadius: '8px', padding: '10px 20px', fontWeight: 'bold' }
    });

    let currentY = 150;
    let currentX = 100;
    const spacingX = 250;

    const addModule = (id: string, label: string, color: string, children: string[]) => {
      // Main Module Node
      newNodes.push({
        id,
        data: { label },
        position: { x: currentX, y: currentY },
        style: { background: '#18181b', color: '#e4e4e7', border: `1px solid ${color}`, borderRadius: '8px', padding: '10px 20px' }
      });
      newEdges.push({ id: `e-system-${id}`, source: 'system', target: id, animated: true, style: { stroke: '#52525b' } });

      // Children
      children.forEach((child, i) => {
        const childId = `${id}-${i}`;
        newNodes.push({
          id: childId,
          data: { label: child },
          position: { x: currentX + (i % 2 === 0 ? -60 : 60), y: currentY + 80 + (Math.floor(i / 2) * 50) },
          style: { background: '#18181b', color: '#a1a1aa', border: `1px dashed ${color}50`, borderRadius: '4px', padding: '5px 10px', fontSize: '12px' }
        });
        newEdges.push({ id: `e-${id}-${childId}`, source: id, target: childId, style: { stroke: `${color}50` } });
      });

      currentX += spacingX;
      if (currentX > 800) {
        currentX = 100;
        currentY += 250;
      }
    };

    // 1. Modulo de Autenticación
    const authChildren = [];
    if (profile.authIntelligence) {
      if (profile.authIntelligence.cookies.length > 0) authChildren.push('Cookies de Sesión');
      if (profile.authIntelligence.usesLocalStorage) authChildren.push('LocalStorage Auth');
    }
    const hasAuthEndpoints = profile.attackSurface.some(e => e.path.includes('auth') || e.path.includes('login') || e.path.includes('register'));
    if (hasAuthEndpoints || authChildren.length > 0) {
      addModule('auth', 'Autenticación & Sesiones', '#ef4444', authChildren.length > 0 ? authChildren : ['Gestión de Acceso']);
    }

    // 2. Gestión de Usuarios / Roles
    const userChildren = [];
    if (profile.businessDictionary?.roles) {
      userChildren.push(...profile.businessDictionary.roles);
    }
    const hasUsers = profile.businessDictionary?.entities.includes('user') || profile.businessDictionary?.entities.includes('account');
    if (hasUsers || userChildren.length > 0) {
      addModule('users', 'Gestión de Usuarios', '#3b82f6', userChildren);
    }

    // 3. Entidades de Negocio (El resto)
    if (profile.businessDictionary?.entities) {
      const coreEntities = profile.businessDictionary.entities.filter(e => e !== 'user' && e !== 'account');
      if (coreEntities.length > 0) {
         addModule('core', 'Lógica de Negocio Core', '#8b5cf6', coreEntities.slice(0, 10)); // max 10
      }
    }

    // 4. Data Models inferidos por Parámetros
    if (profile.parameterIntelligence && profile.parameterIntelligence.topParameters.length > 0) {
      const params = profile.parameterIntelligence.topParameters.map(p => p.name).filter(p => p.toLowerCase().includes('id'));
      if (params.length > 0) {
        addModule('data', 'Data Models (Catálogo)', '#10b981', params.slice(0, 8));
      }
    }

    // 5. GraphQL Types si existen
    if (profile.communicationIntelligence?.graphql.enabled && profile.communicationIntelligence.graphql.types.length > 0) {
      addModule('graphql-types', 'GraphQL Entities', '#ec4899', profile.communicationIntelligence.graphql.types.slice(0, 8));
    }

    // 6. Cloud & Storage 
    if (profile.cloudIntelligence && profile.cloudIntelligence.provider !== 'Unknown') {
      addModule('cloud', 'Gestión de Storage / Nube', '#0ea5e9', profile.cloudIntelligence.services);
    }

    return { nodes: newNodes, edges: newEdges };
  }, [profile]);

  return (
    <div style={{ width: '100%', height: '500px' }} className="rounded-lg overflow-hidden border border-white/5 bg-[#09090b]">
      <ReactFlow nodes={nodes} edges={edges} fitView colorMode="dark">
        <Background color="#27272a" gap={16} />
        <Controls />
        <MiniMap nodeStrokeColor="#3f3f46" nodeColor="#18181b" maskColor="rgba(0, 0, 0, 0.5)" />
      </ReactFlow>
    </div>
  );
}
