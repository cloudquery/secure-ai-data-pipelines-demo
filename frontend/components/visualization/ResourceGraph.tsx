/**
 * Interactive Resource Graph Visualization Component
 */
import React, { useEffect, useRef, useState } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { Card } from '../ui/Card';
import { Badge } from '../ui/Badge';

interface GraphNode {
  id: string;
  label: string;
  type: string;
  provider: string;
  region: string;
  public_access: boolean;
  encryption_enabled: boolean;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  confidence: number;
}

interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

interface ResourceGraphProps {
  data: GraphData;
  width?: number;
  height?: number;
  onNodeClick?: (node: GraphNode) => void;
  onEdgeClick?: (edge: GraphEdge) => void;
}

const NODE_COLORS = {
  low: '#16a34a',
  medium: '#d97706', 
  high: '#ea580c',
  critical: '#dc2626',
};

const PROVIDER_SHAPES = {
  aws: '🟠',
  gcp: '🔵', 
  azure: '🟦',
};

const RESOURCE_TYPE_ICONS = {
  ec2_instance: '💻',
  s3_bucket: '🪣',
  rds_instance: '🗄️',
  lambda_function: '⚡',
  vpc: '🌐',
  security_group: '🛡️',
  load_balancer: '⚖️',
  api_gateway: '🚪',
  iam_role: '👤',
  kms_key: '🔐',
  default: '📦',
};

export const ResourceGraph: React.FC<ResourceGraphProps> = ({
  data,
  width = 800,
  height = 600,
  onNodeClick,
  onEdgeClick,
}) => {
  const graphRef = useRef<any>();
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [highlightNodes, setHighlightNodes] = useState<Set<string>>(new Set());
  const [highlightLinks, setHighlightLinks] = useState<Set<string>>(new Set());

  // Transform data for force graph
  const graphData = {
    nodes: data.nodes.map(node => ({
      ...node,
      val: node.risk_level === 'critical' ? 8 : node.risk_level === 'high' ? 6 : node.risk_level === 'medium' ? 4 : 2,
      color: NODE_COLORS[node.risk_level],
    })),
    links: data.edges.map(edge => ({
      ...edge,
      value: edge.confidence * 5, // Scale confidence to link thickness
    })),
  };

  const handleNodeClick = (node: any) => {
    setSelectedNode(node);
    setSelectedEdge(null);
    
    // Highlight connected nodes and links
    const connectedNodes = new Set<string>();
    const connectedLinks = new Set<string>();
    
    data.edges.forEach(edge => {
      if (edge.source === node.id || edge.target === node.id) {
        connectedLinks.add(edge.id);
        connectedNodes.add(edge.source === node.id ? edge.target : edge.source);
      }
    });
    
    connectedNodes.add(node.id);
    setHighlightNodes(connectedNodes);
    setHighlightLinks(connectedLinks);
    
    onNodeClick?.(node);
  };

  const handleLinkClick = (link: any) => {
    setSelectedEdge(link);
    setSelectedNode(null);
    
    // Highlight connected nodes
    const connectedNodes = new Set([link.source.id || link.source, link.target.id || link.target]);
    setHighlightNodes(connectedNodes);
    setHighlightLinks(new Set([link.id]));
    
    onEdgeClick?.(link);
  };

  const handleBackgroundClick = () => {
    setSelectedNode(null);
    setSelectedEdge(null);
    setHighlightNodes(new Set());
    setHighlightLinks(new Set());
  };

  const nodeCanvasObject = (node: any, ctx: CanvasRenderingContext2D) => {
    const label = node.label || node.id;
    const fontSize = 12;
    const isHighlighted = highlightNodes.has(node.id);
    const opacity = highlightNodes.size > 0 ? (isHighlighted ? 1 : 0.3) : 1;

    // Draw node circle
    ctx.save();
    ctx.globalAlpha = opacity;
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.val, 0, 2 * Math.PI);
    ctx.fillStyle = node.color;
    ctx.fill();
    
    // Draw border if highlighted
    if (isHighlighted) {
      ctx.strokeStyle = '#1f2937';
      ctx.lineWidth = 2;
      ctx.stroke();
    }

    // Draw provider icon
    const providerIcon = PROVIDER_SHAPES[node.provider as keyof typeof PROVIDER_SHAPES] || '⚪';
    ctx.font = '16px Arial';
    ctx.textAlign = 'center';
    ctx.fillStyle = '#ffffff';
    ctx.fillText(providerIcon, node.x, node.y - node.val - 15);

    // Draw resource type icon
    const typeIcon = RESOURCE_TYPE_ICONS[node.type as keyof typeof RESOURCE_TYPE_ICONS] || RESOURCE_TYPE_ICONS.default;
    ctx.font = '14px Arial';
    ctx.fillText(typeIcon, node.x, node.y + 2);

    // Draw label
    ctx.font = `${fontSize}px Arial`;
    ctx.textAlign = 'center';
    ctx.fillStyle = '#1f2937';
    ctx.fillText(label, node.x, node.y + node.val + 15);
    
    ctx.restore();
  };

  const linkCanvasObject = (link: any, ctx: CanvasRenderingContext2D) => {
    const isHighlighted = highlightLinks.has(link.id);
    const opacity = highlightLinks.size > 0 ? (isHighlighted ? 1 : 0.2) : 0.6;
    
    ctx.save();
    ctx.globalAlpha = opacity;
    ctx.strokeStyle = isHighlighted ? '#1f2937' : '#6b7280';
    ctx.lineWidth = isHighlighted ? 3 : Math.max(1, link.value);
    
    // Draw dashed line for low confidence
    if (link.confidence < 0.7) {
      ctx.setLineDash([5, 5]);
    }
    
    ctx.beginPath();
    ctx.moveTo(link.source.x, link.source.y);
    ctx.lineTo(link.target.x, link.target.y);
    ctx.stroke();
    ctx.restore();
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold text-gray-900">Resource Relationship Graph</h3>
        <div className="flex space-x-2">
          <Badge variant="info">{data.nodes.length} Resources</Badge>
          <Badge variant="default">{data.edges.length} Relationships</Badge>
        </div>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3">
          <Card padding="none" className="overflow-hidden">
            <ForceGraph2D
              ref={graphRef}
              graphData={graphData}
              width={width}
              height={height}
              nodeCanvasObject={nodeCanvasObject}
              linkCanvasObject={linkCanvasObject}
              onNodeClick={handleNodeClick}
              onLinkClick={handleLinkClick}
              onBackgroundClick={handleBackgroundClick}
              nodePointerAreaPaint={(node, color, ctx) => {
                ctx.fillStyle = color;
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.val + 5, 0, 2 * Math.PI);
                ctx.fill();
              }}
              linkWidth={link => Math.max(1, link.value)}
              linkDirectionalArrowLength={6}
              linkDirectionalArrowRelPos={1}
              linkDirectionalArrowColor="#6b7280"
              cooldownTicks={100}
              onEngineStop={() => graphRef.current?.zoomToFit(400)}
            />
          </Card>
        </div>
        
        <div className="space-y-4">
          {/* Legend */}
          <Card title="Legend" padding="small">
            <div className="space-y-3">
              <div>
                <h4 className="text-sm font-medium text-gray-900 mb-2">Risk Levels</h4>
                <div className="space-y-1">
                  {Object.entries(NODE_COLORS).map(([level, color]) => (
                    <div key={level} className="flex items-center space-x-2">
                      <div
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: color }}
                      ></div>
                      <span className="text-xs text-gray-600 capitalize">{level}</span>
                    </div>
                  ))}
                </div>
              </div>
              
              <div>
                <h4 className="text-sm font-medium text-gray-900 mb-2">Providers</h4>
                <div className="space-y-1">
                  {Object.entries(PROVIDER_SHAPES).map(([provider, icon]) => (
                    <div key={provider} className="flex items-center space-x-2">
                      <span className="text-sm">{icon}</span>
                      <span className="text-xs text-gray-600 uppercase">{provider}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </Card>

          {/* Selected Node Details */}
          {selectedNode && (
            <Card title="Selected Resource" padding="small">
              <div className="space-y-2">
                <div>
                  <span className="text-xs text-gray-500">Type:</span>
                  <p className="text-sm font-medium">{selectedNode.type}</p>
                </div>
                <div>
                  <span className="text-xs text-gray-500">Provider:</span>
                  <p className="text-sm font-medium uppercase">{selectedNode.provider}</p>
                </div>
                <div>
                  <span className="text-xs text-gray-500">Region:</span>
                  <p className="text-sm font-medium">{selectedNode.region}</p>
                </div>
                <div>
                  <span className="text-xs text-gray-500">Risk Level:</span>
                  <Badge variant={selectedNode.risk_level} size="sm">
                    {selectedNode.risk_level}
                  </Badge>
                </div>
                <div className="flex space-x-2 pt-2">
                  {selectedNode.public_access && (
                    <Badge variant="warning" size="sm">Public</Badge>
                  )}
                  {selectedNode.encryption_enabled && (
                    <Badge variant="success" size="sm">Encrypted</Badge>
                  )}
                </div>
              </div>
            </Card>
          )}

          {/* Selected Edge Details */}
          {selectedEdge && (
            <Card title="Selected Relationship" padding="small">
              <div className="space-y-2">
                <div>
                  <span className="text-xs text-gray-500">Type:</span>
                  <p className="text-sm font-medium">{selectedEdge.type.replace('_', ' ')}</p>
                </div>
                <div>
                  <span className="text-xs text-gray-500">Confidence:</span>
                  <div className="flex items-center space-x-2">
                    <div className="flex-1 bg-gray-200 rounded-full h-2">
                      <div
                        className="bg-blue-600 h-2 rounded-full"
                        style={{ width: `${selectedEdge.confidence * 100}%` }}
                      ></div>
                    </div>
                    <span className="text-sm font-medium">
                      {Math.round(selectedEdge.confidence * 100)}%
                    </span>
                  </div>
                </div>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default ResourceGraph;
