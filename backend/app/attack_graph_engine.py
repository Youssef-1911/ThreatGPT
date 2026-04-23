from typing import Any


# ── Edge label and weight constants ──────────────────────────────────────────
EDGE_LABELS: dict[str, str] = {
    "actor_to_entry_point":     "enters via",
    "entry_point_to_component": "reaches",
    "component_to_asset":       "accesses",
    "threat_to_component":      "targets",
    "threat_to_entry_point":    "exploits",
    "threat_to_asset":          "compromises",
    "component_to_component":   "calls",
}

EDGE_WEIGHTS: dict[str, int] = {
    "threat_to_component":      3,
    "threat_to_asset":          3,
    "threat_to_entry_point":    3,
    "entry_point_to_component": 2,
    "component_to_asset":       2,
    "actor_to_entry_point":     1,
    "component_to_component":   1,
}


class AttackGraphEngine:
    """Builds a deterministic attack graph from parsed architecture and generated threats.

    Only nodes that are connected to at least one threat are included. Edges between
    components are only drawn when both endpoints are threat-relevant, preserving
    scenario engine DFS path traversal while eliminating structural noise.
    """

    # Severities considered for critical path marking (case-insensitive).
    _CRITICAL_SEVERITIES = {"critical", "high"}

    def build_graph(self, parsed_data: dict[str, Any], threats: list[dict[str, Any]]) -> dict[str, Any]:
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        node_ids: set[str] = set()
        edge_keys: set[tuple[str, str, str]] = set()

        actors = parsed_data.get("actors") if isinstance(parsed_data, dict) else []
        components = parsed_data.get("components") if isinstance(parsed_data, dict) else []
        entry_points = parsed_data.get("entry_points") if isinstance(parsed_data, dict) else []
        assets = parsed_data.get("assets") if isinstance(parsed_data, dict) else []
        data_flows = parsed_data.get("data_flows") if isinstance(parsed_data, dict) else []
        trust_boundaries = parsed_data.get("trust_boundaries") if isinstance(parsed_data, dict) else []

        actor_items = actors if isinstance(actors, list) else []
        component_items = components if isinstance(components, list) else []
        entry_point_items = entry_points if isinstance(entry_points, list) else []
        asset_items = assets if isinstance(assets, list) else []
        data_flow_items = data_flows if isinstance(data_flows, list) else []

        # ── Step 1: Build threat-relevant ID sets ────────────────────────────────
        # These sets drive all node/edge filtering decisions below.
        threat_items = threats if isinstance(threats, list) else []
        _unknown = {"", "unknown"}

        threat_relevant_component_ids: set[str] = set()
        threat_relevant_entry_point_ids: set[str] = set()
        threat_relevant_asset_ids: set[str] = set()

        for t in threat_items:
            if not isinstance(t, dict):
                continue
            c = (t.get("affected_component_id") or "").strip()
            e = (t.get("entry_point_id") or "").strip()
            a = (t.get("asset_id") or "").strip()
            if c and c.lower() not in _unknown:
                threat_relevant_component_ids.add(c)
            if e and e.lower() not in _unknown:
                threat_relevant_entry_point_ids.add(e)
            if a and a.lower() not in _unknown:
                threat_relevant_asset_ids.add(a)

        # An actor is eligible when it has at least one data flow toward a
        # threat-relevant component, or toward a component that hosts a
        # threat-relevant entry point.
        threat_relevant_actor_ids: set[str] = set()
        for flow in data_flow_items:
            if not isinstance(flow, dict):
                continue
            src = (flow.get("source_component_id") or "").strip()
            dst = (flow.get("destination_component_id") or "").strip()
            if not src or not dst:
                continue
            if not src.startswith("actor_"):
                continue
            if dst in threat_relevant_component_ids:
                threat_relevant_actor_ids.add(src)
                continue
            # Also eligible if any threat-relevant entry point targets dst.
            for ep in entry_point_items:
                if not isinstance(ep, dict):
                    continue
                if ep.get("target_component_id", "").strip() == dst:
                    ep_id = (ep.get("id") or "").strip()
                    if ep_id in threat_relevant_entry_point_ids:
                        threat_relevant_actor_ids.add(src)
                        break

        # ── Build component_id → trust_zone map ──────────────────────────────────
        component_trust_zone: dict[str, str] = {}
        for comp in component_items:
            if not isinstance(comp, dict):
                continue
            comp_id = comp.get("id")
            trust_zone = comp.get("trust_zone")
            if isinstance(comp_id, str) and comp_id.strip() and isinstance(trust_zone, str) and trust_zone.strip():
                component_trust_zone[comp_id.strip()] = trust_zone.strip().lower()

        # ── Build trust-boundary crossing pairs ──────────────────────────────────
        boundary_crossing_pairs: set[tuple[str, str]] = set()
        trust_boundary_items = trust_boundaries if isinstance(trust_boundaries, list) else []
        for boundary in trust_boundary_items:
            if not isinstance(boundary, dict):
                continue
            crossing_ids = boundary.get("crossing_component_ids")
            if not isinstance(crossing_ids, list):
                continue
            valid_ids = [cid.strip() for cid in crossing_ids if isinstance(cid, str) and cid.strip() and cid.strip().lower() != "unknown"]
            for i in range(len(valid_ids)):
                for j in range(len(valid_ids)):
                    if i != j:
                        boundary_crossing_pairs.add((valid_ids[i], valid_ids[j]))

        index: dict[str, dict[str, str]] = {
            "actor": {},
            "component": {},
            "entry_point": {},
            "asset": {},
            "threat": {},
        }

        warnings_by_node_id: dict[str, list[str]] = {}

        def add_warning(node_id: str | None, message: str) -> None:
            if not node_id:
                return
            warnings_by_node_id.setdefault(node_id, [])
            if message not in warnings_by_node_id[node_id]:
                warnings_by_node_id[node_id].append(message)

        def normalize_identifier(value: Any, fallback: str) -> str:
            if isinstance(value, str) and value.strip() and value.strip().lower() != "unknown":
                return value.strip()
            return fallback

        def unique_node_id(base_id: str) -> str:
            if base_id not in node_ids:
                return base_id
            suffix = 2
            while f"{base_id}__{suffix}" in node_ids:
                suffix += 1
            return f"{base_id}__{suffix}"

        def create_node(
            node_type: str,
            source: dict[str, Any],
            fallback_id: str,
            fallback_name: str,
            index_key: str,
            source_list_id: Any,
            display_name: str | None = None,
        ) -> str:
            raw_id = normalize_identifier(source.get("id"), fallback_id)
            node_id_base = f"{node_type}:{raw_id}"
            node_id = unique_node_id(node_id_base)

            if display_name:
                node_name = display_name
            elif isinstance(source.get("name"), str) and source.get("name", "").strip():
                node_name = source["name"]
            else:
                node_name = fallback_name

            metadata: dict[str, Any] = {
                "source_id": source.get("id"),
                "source": source,
            }

            if node_id != node_id_base:
                metadata["duplicate_id_resolved"] = True
                metadata["resolved_node_id"] = node_id

            node = {
                "id": node_id,
                "type": node_type,
                "name": node_name,
                "metadata": metadata,
            }

            nodes.append(node)
            node_ids.add(node_id)

            if isinstance(source_list_id, str) and source_list_id.strip() and source_list_id.strip().lower() != "unknown":
                index[index_key].setdefault(source_list_id.strip(), node_id)
            if isinstance(source.get("id"), str) and source.get("id", "").strip() and source.get("id", "").strip().lower() != "unknown":
                index[index_key].setdefault(source.get("id").strip(), node_id)

            return node_id

        def add_edge(
            from_node_id: str | None,
            to_node_id: str | None,
            edge_type: str,
            metadata: dict[str, Any],
            warning_node_id: str | None = None,
            warning_message: str | None = None,
        ) -> None:
            if not from_node_id or not to_node_id:
                if warning_message:
                    add_warning(warning_node_id, warning_message)
                return

            if from_node_id not in node_ids or to_node_id not in node_ids:
                if warning_message:
                    add_warning(warning_node_id, warning_message)
                return

            edge_key = (from_node_id, to_node_id, edge_type)
            if edge_key in edge_keys:
                return

            edges.append(
                {
                    "from": from_node_id,
                    "to": to_node_id,
                    "type": edge_type,
                    "label": EDGE_LABELS.get(edge_type, edge_type),
                    "weight": EDGE_WEIGHTS.get(edge_type, 1),
                    "is_critical": False,
                    "metadata": metadata,
                }
            )
            edge_keys.add(edge_key)

        # ── Step 2: Actor nodes (threat-relevant only) ────────────────────────────
        actor_node_by_object: dict[int, str] = {}
        for idx, actor in enumerate(actor_items):
            if not isinstance(actor, dict):
                continue
            actor_raw_id = (actor.get("id") or "").strip()
            if not actor_raw_id or actor_raw_id.lower() in _unknown or actor_raw_id not in threat_relevant_actor_ids:
                continue
            actor_node_id = create_node(
                node_type="actor",
                source=actor,
                fallback_id=f"actor_{idx + 1}",
                fallback_name=f"Actor {idx + 1}",
                index_key="actor",
                source_list_id=actor_raw_id,
            )
            actor_node_by_object[id(actor)] = actor_node_id

        # ── Step 2: Component nodes (threat-relevant only) ────────────────────────
        for idx, component in enumerate(component_items):
            if not isinstance(component, dict):
                continue
            component_raw_id = (component.get("id") or "").strip()
            if not component_raw_id or component_raw_id.lower() in _unknown or component_raw_id not in threat_relevant_component_ids:
                continue
            comp_name = (component.get("name") or "").strip()
            comp_type = (component.get("type") or "unknown").strip()
            display = f"{comp_name} ({comp_type})" if comp_name else f"Component {idx + 1} ({comp_type})"
            create_node(
                node_type="component",
                source=component,
                fallback_id=f"component_{idx + 1}",
                fallback_name=display,
                index_key="component",
                source_list_id=component_raw_id,
                display_name=display,
            )

        # ── Step 2: Entry point nodes (threat-relevant only) ──────────────────────
        entry_points_by_component: dict[str, list[str]] = {}
        entry_point_node_by_object: dict[int, str] = {}
        for idx, entry_point in enumerate(entry_point_items):
            if not isinstance(entry_point, dict):
                continue
            entry_point_raw_id = (entry_point.get("id") or "").strip()
            if not entry_point_raw_id or entry_point_raw_id.lower() in _unknown or entry_point_raw_id not in threat_relevant_entry_point_ids:
                continue
            ep_name = (entry_point.get("name") or "").strip()
            ep_exposure = (entry_point.get("exposure") or "unknown").strip()
            display = f"{ep_name} [{ep_exposure}]" if ep_name else f"Entry Point {idx + 1} [{ep_exposure}]"
            node_id = create_node(
                node_type="entry_point",
                source=entry_point,
                fallback_id=f"entry_point_{idx + 1}",
                fallback_name=display,
                index_key="entry_point",
                source_list_id=entry_point_raw_id,
                display_name=display,
            )
            entry_point_node_by_object[id(entry_point)] = node_id

            target_component_id = entry_point.get("target_component_id")
            if isinstance(target_component_id, str) and target_component_id.strip() and target_component_id.strip().lower() != "unknown":
                entry_points_by_component.setdefault(target_component_id.strip(), []).append(node_id)

        # ── Step 2: Asset nodes (threat-relevant only) ────────────────────────────
        asset_node_by_object: dict[int, str] = {}
        for idx, asset in enumerate(asset_items):
            if not isinstance(asset, dict):
                continue
            asset_raw_id = (asset.get("id") or "").strip()
            if not asset_raw_id or asset_raw_id.lower() in _unknown or asset_raw_id not in threat_relevant_asset_ids:
                continue
            asset_name = (asset.get("name") or "").strip()
            asset_sensitivity = (asset.get("sensitivity") or "unknown").strip()
            display = f"{asset_name} [{asset_sensitivity}]" if asset_name else f"Asset {idx + 1} [{asset_sensitivity}]"
            asset_node_id = create_node(
                node_type="asset",
                source=asset,
                fallback_id=f"asset_{idx + 1}",
                fallback_name=display,
                index_key="asset",
                source_list_id=asset_raw_id,
                display_name=display,
            )
            asset_node_by_object[id(asset)] = asset_node_id

        # ── Step 2+5: Threat nodes (always added) + metadata enrichment ───────────
        threat_node_by_object: dict[int, str] = {}
        for idx, threat in enumerate(threat_items):
            if not isinstance(threat, dict):
                continue
            threat_raw_id = threat.get("id")
            cat = (threat.get("category") or "").strip()
            raw_title = (threat.get("title") or "").strip() or f"Threat {idx + 1}"
            prefix = f"[{cat}] " if cat else ""
            label = prefix + raw_title
            if len(label) > 53:
                label = label[:50] + "\u2026"
            threat_node_id = create_node(
                node_type="threat",
                source=threat,
                fallback_id=f"threat_{idx + 1}",
                fallback_name=label,
                index_key="threat",
                source_list_id=threat_raw_id,
                display_name=label,
            )
            threat_node_by_object[id(threat)] = threat_node_id

            grounded = threat.get("grounded_finding")
            grounded_str = grounded if isinstance(grounded, str) else ""

            # Surface STRIDE, severity, grounding, and risk as top-level metadata fields.
            nodes[-1]["metadata"].update({
                "category": threat.get("category"),
                "severity": threat.get("severity"),
                "grounded_finding": grounded,
                "affected_component_id": threat.get("affected_component_id"),
                "entry_point_id": threat.get("entry_point_id"),
                "asset_id": threat.get("asset_id"),
                "is_grounded": bool(grounded_str.strip() and grounded_str.strip().lower() not in _unknown),
                "risk_score": threat.get("risk_score", 0) if isinstance(threat.get("risk_score"), (int, float)) else 0,
            })

        # ── Edges: actor → entry_point (direct references) ───────────────────────
        actor_entry_point_reference_keys = [
            "entry_point_id",
            "target_entry_point_id",
            "access_entry_point_id",
            "entry_point_ids",
            "target_entry_point_ids",
            "access_entry_point_ids",
        ]
        for actor in actor_items:
            if not isinstance(actor, dict):
                continue
            actor_node_id = actor_node_by_object.get(id(actor))
            if not actor_node_id:
                continue
            for key in actor_entry_point_reference_keys:
                value = actor.get(key)
                candidate_ids: list[str] = []
                if isinstance(value, str):
                    candidate_ids = [value]
                elif isinstance(value, list):
                    candidate_ids = [v for v in value if isinstance(v, str)]
                for entry_point_id in candidate_ids:
                    normalized = entry_point_id.strip()
                    if not normalized or normalized.lower() == "unknown":
                        continue
                    add_edge(
                        actor_node_id,
                        index["entry_point"].get(normalized),
                        "actor_to_entry_point",
                        {"source": "actor_reference", "reference_field": key, "reference_id": normalized},
                    )

        # ── Edges: actor → entry_point (inferred via data flows) ─────────────────
        for flow in data_flow_items:
            if not isinstance(flow, dict):
                continue
            source_id = flow.get("source_component_id")
            destination_id = flow.get("destination_component_id")
            if not isinstance(source_id, str) or not isinstance(destination_id, str):
                continue
            source_id = source_id.strip()
            destination_id = destination_id.strip()
            if not source_id or not destination_id:
                continue
            actor_node_id = index["actor"].get(source_id)
            target_entry_nodes = entry_points_by_component.get(destination_id, [])
            for entry_node_id in target_entry_nodes:
                add_edge(
                    actor_node_id,
                    entry_node_id,
                    "actor_to_entry_point",
                    {
                        "source": "data_flow_inference",
                        "data_flow_id": flow.get("id"),
                        "source_component_id": source_id,
                        "destination_component_id": destination_id,
                    },
                )

        # ── Edges: entry_point → component ───────────────────────────────────────
        for entry_point in entry_point_items:
            if not isinstance(entry_point, dict):
                continue
            entry_node_id = entry_point_node_by_object.get(id(entry_point))
            if not entry_node_id:
                continue
            target_component_id = entry_point.get("target_component_id")
            target_node_id = None
            if isinstance(target_component_id, str) and target_component_id.strip() and target_component_id.strip().lower() != "unknown":
                target_node_id = index["component"].get(target_component_id.strip())
            add_edge(
                entry_node_id,
                target_node_id,
                "entry_point_to_component",
                {
                    "source": "entry_point_target",
                    "target_component_id": target_component_id,
                },
            )

        # ── Edges: component → component (threat-relevant flows only) ─────────────
        # Only drawn when BOTH source and destination are threat-relevant components.
        # This preserves scenario engine DFS for real attack chains while removing
        # structural data flows that carry no threat context.
        for flow in data_flow_items:
            if not isinstance(flow, dict):
                continue
            source_id = flow.get("source_component_id")
            destination_id = flow.get("destination_component_id")
            if not isinstance(source_id, str) or not isinstance(destination_id, str):
                continue
            normalized_source = source_id.strip()
            normalized_destination = destination_id.strip()
            if (
                not normalized_source
                or not normalized_destination
                or normalized_source.lower() == "unknown"
                or normalized_destination.lower() == "unknown"
            ):
                continue
            # Step 3 guard: skip flows where either endpoint is not threat-relevant.
            if (
                normalized_source not in threat_relevant_component_ids
                or normalized_destination not in threat_relevant_component_ids
            ):
                continue
            source_node_id = index["component"].get(normalized_source)
            destination_node_id = index["component"].get(normalized_destination)
            crosses_boundary = (
                (normalized_source, normalized_destination) in boundary_crossing_pairs
                or (
                    component_trust_zone.get(normalized_source, "") != component_trust_zone.get(normalized_destination, "")
                    and component_trust_zone.get(normalized_source, "") != ""
                    and component_trust_zone.get(normalized_destination, "") != ""
                )
            )
            add_edge(
                source_node_id,
                destination_node_id,
                "component_to_component",
                {
                    "source": "data_flow",
                    "data_flow_id": flow.get("id"),
                    "protocol": flow.get("protocol"),
                    "description": flow.get("description"),
                    "trust_boundary_crossing": crosses_boundary,
                },
            )

        # ── Edges: component → asset (explicit references on assets) ─────────────
        asset_component_reference_keys = [
            "component_id",
            "owner_component_id",
            "target_component_id",
            "location_component_id",
            "component_ids",
            "owner_component_ids",
            "target_component_ids",
        ]
        for asset in asset_items:
            if not isinstance(asset, dict):
                continue
            asset_node_id = asset_node_by_object.get(id(asset))
            if not asset_node_id:
                continue
            for key in asset_component_reference_keys:
                value = asset.get(key)
                candidate_ids: list[str] = []
                if isinstance(value, str):
                    candidate_ids = [value]
                elif isinstance(value, list):
                    candidate_ids = [v for v in value if isinstance(v, str)]
                for component_id in candidate_ids:
                    normalized = component_id.strip()
                    if not normalized or normalized.lower() == "unknown":
                        continue
                    add_edge(
                        index["component"].get(normalized),
                        asset_node_id,
                        "component_to_asset",
                        {
                            "source": "asset_reference",
                            "reference_field": key,
                            "component_id": normalized,
                        },
                    )

        # ── Edges: component → asset (inferred from threat mapping) ──────────────
        for threat in threat_items:
            if not isinstance(threat, dict):
                continue
            component_id = threat.get("affected_component_id")
            asset_id = threat.get("asset_id")
            if not isinstance(component_id, str) or not isinstance(asset_id, str):
                continue
            normalized_component_id = component_id.strip()
            normalized_asset_id = asset_id.strip()
            if (
                not normalized_component_id
                or not normalized_asset_id
                or normalized_component_id.lower() == "unknown"
                or normalized_asset_id.lower() == "unknown"
            ):
                continue
            add_edge(
                index["component"].get(normalized_component_id),
                index["asset"].get(normalized_asset_id),
                "component_to_asset",
                {
                    "source": "threat_inference",
                    "threat_id": threat.get("id"),
                },
            )

        # ── Edges: threat → affected_component / asset / entry_point ─────────────
        for threat in threat_items:
            if not isinstance(threat, dict):
                continue
            threat_node_id = threat_node_by_object.get(id(threat))
            if not threat_node_id:
                continue

            affected_component_id = threat.get("affected_component_id")
            if isinstance(affected_component_id, str) and affected_component_id.strip() and affected_component_id.strip().lower() != "unknown":
                normalized_component_id = affected_component_id.strip()
                add_edge(
                    threat_node_id,
                    index["component"].get(normalized_component_id),
                    "threat_to_component",
                    {
                        "source": "threat",
                        "reference_field": "affected_component_id",
                        "reference_id": normalized_component_id,
                    },
                    warning_node_id=threat_node_id,
                    warning_message=f"Unknown affected_component_id: {normalized_component_id}",
                )

            asset_id = threat.get("asset_id")
            if isinstance(asset_id, str) and asset_id.strip() and asset_id.strip().lower() != "unknown":
                normalized_asset_id = asset_id.strip()
                add_edge(
                    threat_node_id,
                    index["asset"].get(normalized_asset_id),
                    "threat_to_asset",
                    {
                        "source": "threat",
                        "reference_field": "asset_id",
                        "reference_id": normalized_asset_id,
                    },
                    warning_node_id=threat_node_id,
                    warning_message=f"Unknown asset_id: {normalized_asset_id}",
                )

            entry_point_id = threat.get("entry_point_id")
            if isinstance(entry_point_id, str) and entry_point_id.strip() and entry_point_id.strip().lower() != "unknown":
                normalized_entry_point_id = entry_point_id.strip()
                add_edge(
                    threat_node_id,
                    index["entry_point"].get(normalized_entry_point_id),
                    "threat_to_entry_point",
                    {
                        "source": "threat",
                        "reference_field": "entry_point_id",
                        "reference_id": normalized_entry_point_id,
                    },
                    warning_node_id=threat_node_id,
                    warning_message=f"Unknown entry_point_id: {normalized_entry_point_id}",
                )

        # ── Attach collected validation warnings to node metadata ─────────────────
        for node in nodes:
            node_warning_list = warnings_by_node_id.get(node["id"])
            if node_warning_list:
                node["metadata"]["warnings"] = node_warning_list

        # ── Score critical paths and build graph_summary ──────────────────────────
        graph_summary = self._score_paths_and_summarize(nodes, edges)

        return {
            "nodes": nodes,
            "edges": edges,
            "graph_summary": graph_summary,
        }

    def _score_paths_and_summarize(
        self,
        nodes: list[dict[str, Any]],
        edges: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Mark critical-path edges with is_critical=True and return graph_summary.

        The critical path connects actor → entry_point → component → asset where
        at least one Critical or High severity threat sits on that path.
        """
        # Build node lookup.
        node_by_id: dict[str, dict[str, Any]] = {n["id"]: n for n in nodes}

        # Collect threat nodes with Critical or High severity.
        high_threat_nodes: list[dict[str, Any]] = []
        for node in nodes:
            if node.get("type") != "threat":
                continue
            severity = (node.get("metadata", {}).get("severity") or "").strip().lower()
            if severity in self._CRITICAL_SEVERITIES:
                high_threat_nodes.append(node)

        # Build a set of (from_id, to_id, type) tuples that belong to critical paths.
        critical_edge_keys: set[tuple[str, str, str]] = set()

        # Build reverse index: entry_point node_id → list of actor node_ids.
        actor_nodes = [n for n in nodes if n.get("type") == "actor"]
        actor_to_entry_edges: dict[str, list[str]] = {}  # entry_point_node_id → [actor_node_ids]
        for edge in edges:
            if edge.get("type") == "actor_to_entry_point":
                ep_id = edge["to"]
                actor_to_entry_edges.setdefault(ep_id, []).append(edge["from"])

        # Build index: entry_point raw_id → entry_point node_id (from index built during graph construction).
        # We read it directly from node metadata.
        entry_point_raw_to_node: dict[str, str] = {}
        for node in nodes:
            if node.get("type") == "entry_point":
                src_id = node.get("metadata", {}).get("source_id")
                if src_id:
                    entry_point_raw_to_node[src_id] = node["id"]

        component_raw_to_node: dict[str, str] = {}
        for node in nodes:
            if node.get("type") == "component":
                src_id = node.get("metadata", {}).get("source_id")
                if src_id:
                    component_raw_to_node[src_id] = node["id"]

        asset_raw_to_node: dict[str, str] = {}
        for node in nodes:
            if node.get("type") == "asset":
                src_id = node.get("metadata", {}).get("source_id")
                if src_id:
                    asset_raw_to_node[src_id] = node["id"]

        critical_entry_asset_pairs: set[tuple[str, str]] = set()

        for threat_node in high_threat_nodes:
            meta = threat_node.get("metadata", {})
            threat_node_id = threat_node["id"]

            ep_raw = (meta.get("entry_point_id") or "").strip()
            comp_raw = (meta.get("affected_component_id") or "").strip()
            asset_raw = (meta.get("asset_id") or "").strip()

            ep_node_id = entry_point_raw_to_node.get(ep_raw) if ep_raw else None
            comp_node_id = component_raw_to_node.get(comp_raw) if comp_raw else None
            asset_node_id = asset_raw_to_node.get(asset_raw) if asset_raw else None

            # Mark threat → component / entry_point / asset edges.
            if comp_node_id:
                critical_edge_keys.add((threat_node_id, comp_node_id, "threat_to_component"))
            if ep_node_id:
                critical_edge_keys.add((threat_node_id, ep_node_id, "threat_to_entry_point"))
            if asset_node_id:
                critical_edge_keys.add((threat_node_id, asset_node_id, "threat_to_asset"))

            # Mark entry_point → component edge.
            if ep_node_id and comp_node_id:
                critical_edge_keys.add((ep_node_id, comp_node_id, "entry_point_to_component"))
                critical_entry_asset_pairs.add((ep_node_id, asset_node_id or ""))

            # Mark component → asset edge.
            if comp_node_id and asset_node_id:
                critical_edge_keys.add((comp_node_id, asset_node_id, "component_to_asset"))

            # Mark actor → entry_point edges for all actors that reach this entry point.
            if ep_node_id:
                for actor_node_id in actor_to_entry_edges.get(ep_node_id, []):
                    critical_edge_keys.add((actor_node_id, ep_node_id, "actor_to_entry_point"))

        # Apply is_critical flag to all edges.
        for edge in edges:
            edge_key = (edge["from"], edge["to"], edge["type"])
            edge["is_critical"] = edge_key in critical_edge_keys

        # ── Build graph_summary ───────────────────────────────────────────────────
        threat_nodes = [n for n in nodes if n.get("type") == "threat"]
        entry_point_nodes = [n for n in nodes if n.get("type") == "entry_point"]
        asset_nodes = [n for n in nodes if n.get("type") == "asset"]

        critical_count = sum(
            1 for n in threat_nodes
            if (n.get("metadata", {}).get("severity") or "").strip().lower() == "critical"
        )
        high_count = sum(
            1 for n in threat_nodes
            if (n.get("metadata", {}).get("severity") or "").strip().lower() == "high"
        )

        # Distinct critical paths = distinct (entry_point, asset) pairs with a critical/high threat.
        critical_path_count = len({pair for pair in critical_entry_asset_pairs if pair[0] and pair[1]})

        return {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "threat_count": len(threat_nodes),
            "critical_threat_count": critical_count,
            "high_threat_count": high_count,
            "critical_paths": critical_path_count,
            "entry_points_covered": len(entry_point_nodes),
            "assets_at_risk": len(asset_nodes),
        }
