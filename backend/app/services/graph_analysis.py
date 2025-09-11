"""
Graph neural network analysis for cloud resource relationship detection.
"""
import networkx as nx
import numpy as np
from typing import Dict, Any, List, Tuple, Optional, Set
from uuid import UUID
from sqlalchemy.orm import Session
from dataclasses import dataclass
import json
from datetime import datetime

from ..models import CloudResource, ResourceRelationship, SecurityFinding


@dataclass
class GraphAnalysisResult:
    """Result of graph analysis."""
    attack_paths: List[Dict[str, Any]]
    centrality_scores: Dict[str, float]
    vulnerability_clusters: List[Dict[str, Any]]
    recommendations: List[str]
    graph_metrics: Dict[str, Any]


class CloudResourceGraph:
    """Graph representation of cloud resources and their relationships."""

    def __init__(self, db: Session):
        self.db = db
        self.graph = nx.DiGraph()
        self.resource_nodes = {}
        self.relationship_edges = {}

    def build_graph_from_db(self, provider_filter: Optional[str] = None) -> None:
        """Build graph from database resources and relationships."""

        # Query resources
        query = self.db.query(CloudResource)
        if provider_filter:
            query = query.join(CloudResource.provider).filter(
                CloudResource.provider.has(name=provider_filter)
            )

        resources = query.all()

        # Add resource nodes
        for resource in resources:
            node_attrs = self._create_node_attributes(resource)
            self.graph.add_node(str(resource.id), **node_attrs)
            self.resource_nodes[str(resource.id)] = resource

        # Query and add relationships
        relationships = self.db.query(ResourceRelationship).join(
            CloudResource, ResourceRelationship.source_resource_id == CloudResource.id
        )

        if provider_filter:
            relationships = relationships.join(CloudResource.provider).filter(
                CloudResource.provider.has(name=provider_filter)
            )

        for rel in relationships.all():
            source_id = str(rel.source_resource_id)
            target_id = str(rel.target_resource_id)

            if source_id in self.graph.nodes and target_id in self.graph.nodes:
                edge_attrs = self._create_edge_attributes(rel)
                self.graph.add_edge(source_id, target_id, **edge_attrs)
                self.relationship_edges[f"{source_id}-{target_id}"] = rel

    def _create_node_attributes(self, resource: CloudResource) -> Dict[str, Any]:
        """Create node attributes for a resource."""

        # Calculate risk score based on security findings
        findings = self.db.query(SecurityFinding).filter(
            SecurityFinding.resource_id == resource.id
        ).all()

        risk_score = sum(finding.risk_score for finding in findings) / \
            len(findings) if findings else 0.0

        return {
            "resource_type": resource.resource_type,
            "service_name": resource.service_name,
            "region": resource.region,
            "public_access": resource.public_access,
            "encryption_enabled": resource.encryption_enabled,
            "risk_score": risk_score,
            "finding_count": len(findings),
            "provider": resource.provider.name if resource.provider else "unknown"
        }

    def _create_edge_attributes(self, relationship: ResourceRelationship) -> Dict[str, Any]:
        """Create edge attributes for a relationship."""

        return {
            "relationship_type": relationship.relationship_type,
            "confidence": relationship.confidence_score,
            "discovered_at": relationship.discovered_at.isoformat() if relationship.discovered_at else None
        }


class GraphNeuralAnalyzer:
    """Graph neural network analyzer for security analysis."""

    def __init__(self, db: Session):
        self.db = db
        self.graph_builder = CloudResourceGraph(db)

    def analyze_attack_paths(
        self,
        source_resources: List[UUID] = None,
        target_resources: List[UUID] = None,
        max_path_length: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Analyze potential attack paths using graph analysis.

        Args:
            source_resources: Starting points for attack paths
            target_resources: Target resources to reach
            max_path_length: Maximum path length to consider

        Returns:
            List of potential attack paths with risk scores
        """

        self.graph_builder.build_graph_from_db()
        graph = self.graph_builder.graph

        attack_paths = []

        # If no specific sources/targets, find high-risk paths
        if not source_resources or not target_resources:
            attack_paths.extend(
                self._find_privilege_escalation_paths(graph, max_path_length))
            attack_paths.extend(
                self._find_data_exfiltration_paths(graph, max_path_length))
            attack_paths.extend(
                self._find_lateral_movement_paths(graph, max_path_length))
        else:
            # Find paths between specific resources
            for source in source_resources:
                for target in target_resources:
                    paths = self._find_paths_between_resources(
                        graph, str(source), str(target), max_path_length
                    )
                    attack_paths.extend(paths)

        # Score and rank paths
        scored_paths = self._score_attack_paths(attack_paths)

        return sorted(scored_paths, key=lambda x: x["risk_score"], reverse=True)

    def calculate_centrality_metrics(self) -> Dict[str, Dict[str, float]]:
        """Calculate centrality metrics for resources."""

        self.graph_builder.build_graph_from_db()
        graph = self.graph_builder.graph

        metrics = {
            "betweenness_centrality": nx.betweenness_centrality(graph),
            "closeness_centrality": nx.closeness_centrality(graph),
            "degree_centrality": nx.degree_centrality(graph),
            "eigenvector_centrality": nx.eigenvector_centrality(graph, max_iter=1000),
            "pagerank": nx.pagerank(graph)
        }

        return metrics

    def identify_vulnerability_clusters(self) -> List[Dict[str, Any]]:
        """Identify clusters of vulnerable resources."""

        self.graph_builder.build_graph_from_db()
        graph = self.graph_builder.graph

        # Find nodes with high risk scores
        high_risk_nodes = [
            node for node, attrs in graph.nodes(data=True)
            if attrs.get("risk_score", 0) >= 7.0
        ]

        # Find connected components of high-risk nodes
        high_risk_subgraph = graph.subgraph(high_risk_nodes)
        clusters = list(nx.connected_components(
            high_risk_subgraph.to_undirected()))

        cluster_analysis = []
        for i, cluster in enumerate(clusters):
            if len(cluster) > 1:  # Only consider clusters with multiple nodes
                cluster_info = self._analyze_cluster(graph, cluster, i)
                cluster_analysis.append(cluster_info)

        return cluster_analysis

    def detect_anomalous_relationships(self) -> List[Dict[str, Any]]:
        """Detect anomalous or suspicious relationships."""

        self.graph_builder.build_graph_from_db()
        graph = self.graph_builder.graph

        anomalies = []

        # Detect unusual relationship patterns
        for node in graph.nodes():
            node_attrs = graph.nodes[node]

            # Check for resources with unusually high connectivity
            in_degree = graph.in_degree(node)
            out_degree = graph.out_degree(node)

            if in_degree > 10 or out_degree > 10:  # Threshold for high connectivity
                anomalies.append({
                    "type": "high_connectivity",
                    "resource_id": node,
                    "resource_type": node_attrs.get("resource_type"),
                    "in_degree": in_degree,
                    "out_degree": out_degree,
                    "risk_level": "medium",
                    "description": f"Resource has unusually high connectivity ({in_degree} in, {out_degree} out)"
                })

            # Check for public resources with many connections
            if node_attrs.get("public_access") and (in_degree + out_degree) > 5:
                anomalies.append({
                    "type": "public_high_connectivity",
                    "resource_id": node,
                    "resource_type": node_attrs.get("resource_type"),
                    "total_connections": in_degree + out_degree,
                    "risk_level": "high",
                    "description": "Public resource with high connectivity poses elevated risk"
                })

        return anomalies

    def _find_privilege_escalation_paths(self, graph: nx.DiGraph, max_length: int) -> List[Dict[str, Any]]:
        """Find potential privilege escalation paths."""

        paths = []

        # Look for paths from low-privilege to high-privilege resources
        for source in graph.nodes():
            source_attrs = graph.nodes[source]

            # Start from resources with potential initial access
            if (source_attrs.get("public_access") or
                    source_attrs.get("resource_type") in ["lambda_function", "api_gateway"]):

                # Find paths to high-privilege resources
                for target in graph.nodes():
                    target_attrs = graph.nodes[target]

                    if (target_attrs.get("resource_type") in ["iam_role", "iam_user", "admin_access"] and
                            source != target):

                        try:
                            path = nx.shortest_path(graph, source, target)
                            if len(path) <= max_length and len(path) > 1:
                                paths.append({
                                    "type": "privilege_escalation",
                                    "path": path,
                                    "source_resource": source_attrs,
                                    "target_resource": target_attrs,
                                    "path_length": len(path) - 1
                                })
                        except nx.NetworkXNoPath:
                            continue

        return paths

    def _find_data_exfiltration_paths(self, graph: nx.DiGraph, max_length: int) -> List[Dict[str, Any]]:
        """Find potential data exfiltration paths."""

        paths = []

        # Look for paths from data stores to external access points
        data_stores = [
            node for node, attrs in graph.nodes(data=True)
            if attrs.get("resource_type") in ["s3_bucket", "rds_instance", "dynamodb_table"]
        ]

        external_access = [
            node for node, attrs in graph.nodes(data=True)
            if attrs.get("public_access") or attrs.get("resource_type") in ["api_gateway", "load_balancer"]
        ]

        for data_store in data_stores:
            for external in external_access:
                if data_store != external:
                    try:
                        path = nx.shortest_path(graph, data_store, external)
                        if len(path) <= max_length and len(path) > 1:
                            paths.append({
                                "type": "data_exfiltration",
                                "path": path,
                                "data_store": graph.nodes[data_store],
                                "external_access": graph.nodes[external],
                                "path_length": len(path) - 1
                            })
                    except nx.NetworkXNoPath:
                        continue

        return paths

    def _find_lateral_movement_paths(self, graph: nx.DiGraph, max_length: int) -> List[Dict[str, Any]]:
        """Find potential lateral movement paths."""

        paths = []

        # Look for paths between different network segments or accounts
        for source in graph.nodes():
            source_attrs = graph.nodes[source]
            source_region = source_attrs.get("region")

            for target in graph.nodes():
                target_attrs = graph.nodes[target]
                target_region = target_attrs.get("region")

                # Look for cross-region or cross-service movement
                if (source != target and
                    (source_region != target_region or
                     source_attrs.get("service_name") != target_attrs.get("service_name"))):

                    try:
                        path = nx.shortest_path(graph, source, target)
                        if 2 <= len(path) <= max_length:
                            paths.append({
                                "type": "lateral_movement",
                                "path": path,
                                "source_region": source_region,
                                "target_region": target_region,
                                "path_length": len(path) - 1
                            })
                    except nx.NetworkXNoPath:
                        continue

        return paths[:50]  # Limit to prevent too many results

    def _find_paths_between_resources(
        self,
        graph: nx.DiGraph,
        source: str,
        target: str,
        max_length: int
    ) -> List[Dict[str, Any]]:
        """Find all paths between two specific resources."""

        paths = []

        try:
            # Find all simple paths (no cycles)
            all_paths = nx.all_simple_paths(
                graph, source, target, cutoff=max_length)

            for path in all_paths:
                if len(path) > 1:
                    paths.append({
                        "type": "direct_path",
                        "path": path,
                        "path_length": len(path) - 1,
                        "source_attrs": graph.nodes[source],
                        "target_attrs": graph.nodes[target]
                    })

        except nx.NetworkXNoPath:
            pass

        return paths

    def _score_attack_paths(self, paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score attack paths based on feasibility and impact."""

        scored_paths = []

        for path_info in paths:
            path = path_info["path"]

            # Base score factors
            length_penalty = len(path) * 0.5  # Longer paths are less likely

            # Risk contribution from nodes in path
            node_risk = 0.0
            for node in path:
                node_attrs = self.graph_builder.graph.nodes[node]
                node_risk += node_attrs.get("risk_score", 0.0)

            avg_node_risk = node_risk / len(path)

            # Risk contribution from path type
            type_multiplier = {
                "privilege_escalation": 2.0,
                "data_exfiltration": 1.8,
                "lateral_movement": 1.5,
                "direct_path": 1.0
            }.get(path_info["type"], 1.0)

            # Calculate final risk score
            risk_score = (avg_node_risk * type_multiplier) - length_penalty
            risk_score = max(0.0, min(10.0, risk_score))  # Clamp to 0-10

            path_info["risk_score"] = risk_score
            path_info["scoring_factors"] = {
                "avg_node_risk": avg_node_risk,
                "type_multiplier": type_multiplier,
                "length_penalty": length_penalty
            }

            scored_paths.append(path_info)

        return scored_paths

    def _analyze_cluster(self, graph: nx.DiGraph, cluster: Set[str], cluster_id: int) -> Dict[str, Any]:
        """Analyze a vulnerability cluster."""

        cluster_nodes = list(cluster)
        subgraph = graph.subgraph(cluster_nodes)

        # Calculate cluster metrics
        total_risk = sum(
            graph.nodes[node].get("risk_score", 0.0)
            for node in cluster_nodes
        )
        avg_risk = total_risk / len(cluster_nodes)

        # Identify resource types in cluster
        resource_types = {}
        for node in cluster_nodes:
            res_type = graph.nodes[node].get("resource_type", "unknown")
            resource_types[res_type] = resource_types.get(res_type, 0) + 1

        # Check for public access in cluster
        public_resources = [
            node for node in cluster_nodes
            if graph.nodes[node].get("public_access", False)
        ]

        return {
            "cluster_id": cluster_id,
            "size": len(cluster_nodes),
            "total_risk_score": total_risk,
            "average_risk_score": avg_risk,
            "resource_types": resource_types,
            "public_resources_count": len(public_resources),
            "internal_connections": subgraph.number_of_edges(),
            "density": nx.density(subgraph),
            "nodes": cluster_nodes,
            "risk_level": "critical" if avg_risk >= 8 else "high" if avg_risk >= 6 else "medium"
        }
