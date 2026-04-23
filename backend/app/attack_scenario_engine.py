from typing import Any


class AttackScenarioEngine:
    """Builds deterministic attack scenarios from an attack graph and generated threats."""

    PATH_EDGE_TYPES = {
        "entry_point_to_component",
        "component_to_component",
        "component_to_asset",
    }

    # Depth and count limits prevent path explosion in large graphs.
    MAX_PATH_DEPTH = 8
    MAX_PATHS_PER_PAIR = 3

    THREAT_LINK_EDGE_TYPES = {
        "threat_to_component",
        "threat_to_asset",
        "threat_to_entry_point",
    }

    SEVERITY_RANK = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    def generate_scenarios(
        self,
        graph: dict[str, Any],
        parsed_data: dict[str, Any],
        threats: list[dict[str, Any]],
    ) -> dict[str, Any]:
        missing_fields: list[str] = []

        nodes = graph.get("nodes") if isinstance(graph, dict) else None
        edges = graph.get("edges") if isinstance(graph, dict) else None

        if not isinstance(nodes, list):
            missing_fields.append("graph.nodes")
            nodes = []

        if not isinstance(edges, list):
            missing_fields.append("graph.edges")
            edges = []

        node_by_id: dict[str, dict[str, Any]] = {}
        entry_point_node_ids: list[str] = []
        asset_node_ids: list[str] = []

        for index, node in enumerate(nodes):
            if not isinstance(node, dict):
                missing_fields.append(f"graph.nodes[{index}]")
                continue

            node_id = node.get("id")
            node_type = node.get("type")
            node_name = node.get("name")
            node_metadata = node.get("metadata")

            if not isinstance(node_id, str) or not node_id.strip():
                missing_fields.append(f"graph.nodes[{index}].id")
                continue
            if not isinstance(node_type, str) or not node_type.strip():
                missing_fields.append(f"graph.nodes[{index}].type")
                continue
            if not isinstance(node_name, str):
                missing_fields.append(f"graph.nodes[{index}].name")
                continue
            if not isinstance(node_metadata, dict):
                missing_fields.append(f"graph.nodes[{index}].metadata")
                continue

            normalized_node_id = node_id.strip()
            if normalized_node_id in node_by_id:
                missing_fields.append(f"graph.nodes[{index}].id_duplicate")
                continue

            node_by_id[normalized_node_id] = node

            if node_type == "entry_point":
                entry_point_node_ids.append(normalized_node_id)
            elif node_type == "asset":
                asset_node_ids.append(normalized_node_id)

        outgoing_edges: dict[str, list[dict[str, Any]]] = {}
        threat_edges: list[dict[str, Any]] = []

        for index, edge in enumerate(edges):
            if not isinstance(edge, dict):
                missing_fields.append(f"graph.edges[{index}]")
                continue

            from_node = edge.get("from")
            to_node = edge.get("to")
            edge_type = edge.get("type")
            edge_metadata = edge.get("metadata")

            if not isinstance(from_node, str) or not from_node.strip():
                missing_fields.append(f"graph.edges[{index}].from")
                continue
            if not isinstance(to_node, str) or not to_node.strip():
                missing_fields.append(f"graph.edges[{index}].to")
                continue
            if not isinstance(edge_type, str) or not edge_type.strip():
                missing_fields.append(f"graph.edges[{index}].type")
                continue
            if not isinstance(edge_metadata, dict):
                missing_fields.append(f"graph.edges[{index}].metadata")
                continue

            normalized_from = from_node.strip()
            normalized_to = to_node.strip()
            if normalized_from not in node_by_id:
                missing_fields.append(f"graph.edges[{index}].from_unknown")
                continue
            if normalized_to not in node_by_id:
                missing_fields.append(f"graph.edges[{index}].to_unknown")
                continue

            if edge_type in self.PATH_EDGE_TYPES:
                outgoing_edges.setdefault(normalized_from, []).append(edge)
            if edge_type in self.THREAT_LINK_EDGE_TYPES:
                threat_edges.append(edge)

        if not entry_point_node_ids:
            missing_fields.append("graph.entry_points")

        if not asset_node_ids:
            missing_fields.append("graph.assets")

        all_path_results: list[list[str]] = []
        for entry_point_node_id in entry_point_node_ids:
            for asset_node_id in asset_node_ids:
                paths = self._find_paths(
                    start_node_id=entry_point_node_id,
                    target_node_id=asset_node_id,
                    outgoing_edges=outgoing_edges,
                )
                all_path_results.extend(paths)

        # Deduplicate then rank: paths that cross trust boundaries and carry high-severity threats first.
        seen_path_signatures: set[tuple[str, ...]] = set()
        unique_paths: list[list[str]] = []
        for path in all_path_results:
            signature = tuple(path)
            if signature not in seen_path_signatures:
                seen_path_signatures.add(signature)
                unique_paths.append(path)

        unique_paths.sort(key=lambda p: self._path_score(p, outgoing_edges), reverse=True)

        scenarios: list[dict[str, Any]] = []
        parsed_threats = threats if isinstance(threats, list) else []
        for index, path in enumerate(unique_paths):
            entry_point_node_id = path[0]
            target_asset_node_id = path[-1]

            threat_ids = self._resolve_threat_ids_for_path(
                path=path,
                threat_edges=threat_edges,
                nodes_by_id=node_by_id,
                threats=parsed_threats,
            )

            scenario = {
                "id": f"scenario_{index + 1}",
                "title": self._build_scenario_title(
                    entry_node=node_by_id[entry_point_node_id],
                    asset_node=node_by_id[target_asset_node_id],
                ),
                "entry_point_id": entry_point_node_id,
                "target_asset_id": target_asset_node_id,
                "threat_ids": threat_ids,
                "steps": self._build_steps(path=path, nodes_by_id=node_by_id, outgoing_edges=outgoing_edges),
                "risk_level": self._derive_risk_level(threat_ids=threat_ids, threats=parsed_threats),
                "recommended_controls": self._build_recommended_controls(threat_ids=threat_ids, threats=parsed_threats),
            }
            scenarios.append(scenario)

        if not scenarios:
            missing_fields.append("scenarios")

        # parsed_data is accepted for deterministic extension points and compatibility with graph-generation context.
        if not isinstance(parsed_data, dict):
            missing_fields.append("parsed_data")

        # TODO: Add AI-assisted scenario ranking to prioritize scenarios by exploitability and impact.
        # TODO: Add natural-language scenario explanations tailored for analyst and executive audiences.
        # TODO: Add deterministic + probabilistic scenario scoring that combines graph depth, severity, and controls.

        deduplicated_missing_fields = list(dict.fromkeys(missing_fields))
        return {
            "status": "ready" if not deduplicated_missing_fields else "invalid_output",
            "missing_fields": deduplicated_missing_fields,
            "scenarios": scenarios,
        }

    def _find_paths(
        self,
        start_node_id: str,
        target_node_id: str,
        outgoing_edges: dict[str, list[dict[str, Any]]],
    ) -> list[list[str]]:
        """Find up to MAX_PATHS_PER_PAIR distinct paths using depth-limited DFS.

        Unlike BFS (which only returns the shortest path), this discovers all
        structurally distinct attack routes including longer paths that traverse
        more components — often the ones that cross trust boundaries.
        """
        found: list[list[str]] = []

        def dfs(current: str, path: list[str], visited: set[str]) -> None:
            if len(found) >= self.MAX_PATHS_PER_PAIR:
                return
            if len(path) > self.MAX_PATH_DEPTH:
                return
            if current == target_node_id:
                found.append(list(path))
                return
            for edge in outgoing_edges.get(current, []):
                nxt = edge["to"]
                if nxt not in visited:
                    visited.add(nxt)
                    path.append(nxt)
                    dfs(nxt, path, visited)
                    path.pop()
                    visited.discard(nxt)

        dfs(start_node_id, [start_node_id], {start_node_id})
        return found

    def _path_score(
        self,
        path: list[str],
        outgoing_edges: dict[str, list[dict[str, Any]]],
    ) -> tuple[int, int]:
        """Score a path for ranking: (boundary_crossings, path_length_penalty).

        Higher boundary crossings = higher risk = ranked first.
        Shorter paths are preferred as tiebreaker (negative length).
        """
        crossings = 0
        for i in range(len(path) - 1):
            from_id = path[i]
            to_id = path[i + 1]
            for edge in outgoing_edges.get(from_id, []):
                if edge.get("to") == to_id:
                    meta = edge.get("metadata") or {}
                    if meta.get("trust_boundary_crossing"):
                        crossings += 1
                    break
        return (crossings, -len(path))

    def _build_scenario_title(self, entry_node: dict[str, Any], asset_node: dict[str, Any]) -> str:
        entry_name = entry_node.get("name") if isinstance(entry_node.get("name"), str) else "Entry Point"
        asset_name = asset_node.get("name") if isinstance(asset_node.get("name"), str) else "Asset"
        return f"Attack path from {entry_name} to {asset_name}"

    def _build_steps(
        self,
        path: list[str],
        nodes_by_id: dict[str, dict[str, Any]],
        outgoing_edges: dict[str, list[dict[str, Any]]],
    ) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []

        for index in range(len(path) - 1):
            from_node_id = path[index]
            to_node_id = path[index + 1]
            edge = self._find_edge(from_node_id, to_node_id, outgoing_edges)

            from_name = nodes_by_id[from_node_id].get("name")
            to_name = nodes_by_id[to_node_id].get("name")
            edge_type = edge.get("type") if isinstance(edge, dict) else "unknown"

            steps.append(
                {
                    "step_number": index + 1,
                    "from_node_id": from_node_id,
                    "to_node_id": to_node_id,
                    "description": self._describe_step(
                        edge_type=edge_type,
                        from_name=from_name if isinstance(from_name, str) else from_node_id,
                        to_name=to_name if isinstance(to_name, str) else to_node_id,
                    ),
                }
            )

        return steps

    def _find_edge(
        self,
        from_node_id: str,
        to_node_id: str,
        outgoing_edges: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        for edge in outgoing_edges.get(from_node_id, []):
            if edge.get("to") == to_node_id:
                return edge
        return {}

    def _describe_step(self, edge_type: str, from_name: str, to_name: str) -> str:
        if edge_type == "entry_point_to_component":
            return f"Attacker uses entry point '{from_name}' to reach component '{to_name}'."
        if edge_type == "component_to_component":
            return f"Attack traverses from component '{from_name}' to component '{to_name}'."
        if edge_type == "component_to_asset":
            return f"Attack reaches target asset '{to_name}' through component '{from_name}'."
        return f"Attack moves from '{from_name}' to '{to_name}'."

    def _resolve_threat_ids_for_path(
        self,
        path: list[str],
        threat_edges: list[dict[str, Any]],
        nodes_by_id: dict[str, dict[str, Any]],
        threats: list[dict[str, Any]],
    ) -> list[str]:
        path_node_set = set(path)
        matched_threat_ids: set[str] = set()

        for edge in threat_edges:
            from_node_id = edge.get("from")
            to_node_id = edge.get("to")
            if not isinstance(from_node_id, str) or not isinstance(to_node_id, str):
                continue
            if to_node_id not in path_node_set:
                continue

            threat_node = nodes_by_id.get(from_node_id)
            if not isinstance(threat_node, dict):
                continue
            if threat_node.get("type") != "threat":
                continue

            metadata = threat_node.get("metadata")
            source_id = metadata.get("source_id") if isinstance(metadata, dict) else None
            if isinstance(source_id, str) and source_id.strip():
                matched_threat_ids.add(source_id.strip())

        entry_node = nodes_by_id[path[0]]
        target_asset_node = nodes_by_id[path[-1]]

        entry_source_id = self._extract_source_id(entry_node)
        asset_source_id = self._extract_source_id(target_asset_node)
        path_component_source_ids = {
            self._extract_source_id(nodes_by_id[node_id])
            for node_id in path
            if nodes_by_id[node_id].get("type") == "component"
        }
        path_component_source_ids.discard("")

        for index, threat in enumerate(threats):
            if not isinstance(threat, dict):
                continue

            threat_id = threat.get("id")
            if not isinstance(threat_id, str) or not threat_id.strip():
                threat_id = f"threat_{index + 1}"

            affected_component_id = threat.get("affected_component_id")
            asset_id = threat.get("asset_id")
            entry_point_id = threat.get("entry_point_id")

            component_match = isinstance(affected_component_id, str) and affected_component_id.strip() in path_component_source_ids
            asset_match = isinstance(asset_id, str) and asset_id.strip() and asset_id.strip() == asset_source_id
            entry_match = isinstance(entry_point_id, str) and entry_point_id.strip() and entry_point_id.strip() == entry_source_id

            if component_match or asset_match or entry_match:
                matched_threat_ids.add(str(threat_id).strip())

        return sorted(matched_threat_ids)

    def _extract_source_id(self, node: dict[str, Any]) -> str:
        metadata = node.get("metadata")
        if not isinstance(metadata, dict):
            return ""

        source_id = metadata.get("source_id")
        if isinstance(source_id, str):
            return source_id.strip()

        return ""

    def _derive_risk_level(self, threat_ids: list[str], threats: list[dict[str, Any]]) -> str:
        threat_by_id: dict[str, dict[str, Any]] = {}
        for index, threat in enumerate(threats):
            if not isinstance(threat, dict):
                continue
            raw_id = threat.get("id")
            if isinstance(raw_id, str) and raw_id.strip():
                threat_by_id[raw_id.strip()] = threat
            else:
                threat_by_id[f"threat_{index + 1}"] = threat

        highest = 0
        for threat_id in threat_ids:
            threat = threat_by_id.get(threat_id)
            if not isinstance(threat, dict):
                continue
            severity = threat.get("severity")
            if not isinstance(severity, str):
                continue
            highest = max(highest, self.SEVERITY_RANK.get(severity.strip().lower(), 0))

        if highest >= 4:
            return "critical"
        if highest == 3:
            return "high"
        if highest == 2:
            return "medium"
        if highest == 1:
            return "low"
        return "medium"

    def _build_recommended_controls(
        self,
        threat_ids: list[str],
        threats: list[dict[str, Any]],
    ) -> list[str]:
        threat_by_id: dict[str, dict[str, Any]] = {}
        for index, threat in enumerate(threats):
            if not isinstance(threat, dict):
                continue
            raw_id = threat.get("id")
            if isinstance(raw_id, str) and raw_id.strip():
                threat_by_id[raw_id.strip()] = threat
            else:
                threat_by_id[f"threat_{index + 1}"] = threat

        controls: list[str] = []
        for threat_id in threat_ids:
            threat = threat_by_id.get(threat_id)
            if not isinstance(threat, dict):
                continue
            mitigation = threat.get("mitigation")
            if isinstance(mitigation, str) and mitigation.strip() and mitigation.strip() not in controls:
                controls.append(mitigation.strip())

        if controls:
            return controls

        return [
            "Apply least privilege and segment trust zones around critical components.",
            "Harden entry points with strong authentication, authorization, and input validation.",
            "Add monitoring and alerting for suspicious lateral movement and asset access.",
        ]
