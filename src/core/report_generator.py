"""Generate professional HTML reports for command analysis and batch processing."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from core.mitre import get_attackcti_cache


# MITRE ATT&CK kill-chain phase mapping; based on MITRE Kill Chain Phases
KILL_CHAIN_PHASES = {
    "T1059": 3,  # Execution
    "T1218": 3,  # Execution (Signed Binary Proxy Execution)
    "T1027": 2,  # Defense Evasion (Obfuscation)
    "T1105": 1,  # Initial Access / Command & Control (Ingress Tool Transfer)
    "T1071": 6,  # Command & Control (Application Layer Protocol)
    "T1543": 4,  # Persistence (Create or Modify System Process)
    "T1055": 2,  # Defense Evasion / Privilege Escalation (Process Injection)
}

PHASE_NAMES = {
    0: "Reconnaissance",
    1: "Initial Access / C2",
    2: "Defense Evasion",
    3: "Execution",
    4: "Persistence",
    5: "Privilege Escalation",
    6: "Command & Control",
    7: "Exfiltration",
    8: "Impact",
}


def _get_technique_details(technique_id: str) -> Dict[str, Any]:
    """Fetch technique details from MITRE ATT&CK cache."""
    try:
        cache = get_attackcti_cache()
        techniques = cache.get("techniques", {})
        return techniques.get(technique_id, {
            "id": technique_id,
            "name": "Unknown",
            "description": "No description available",
        })
    except Exception:
        return {
            "id": technique_id,
            "name": "Unknown",
            "description": "No description available",
        }


def _resolve_display_name(mitre: Dict[str, Any], fallback: str = "Unknown") -> str:
    """Choose the most informative display name from MITRE mapping fields."""
    tech_id = str(mitre.get("technique_id", "") or "")
    sub_id = str(mitre.get("subtechnique_id", "") or "")
    tech_name = str(mitre.get("technique", "") or "")
    sub_name = str(mitre.get("subtechnique", "") or "")

    if sub_name and sub_name not in {"Unknown", tech_id, sub_id}:
        return sub_name
    if tech_name and tech_name not in {"Unknown", tech_id}:
        return tech_name
    if sub_name:
        return sub_name
    if tech_name:
        return tech_name
    if sub_id:
        return sub_id
    if tech_id:
        return tech_id
    return fallback


def _build_html_header(title: str) -> str:
    """Build HTML <head> section with embedded CSS."""
    css = """
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        color: #2d3748;
        line-height: 1.6;
        padding: 20px;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        background: white;
        border-radius: 8px;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
        overflow: hidden;
    }
    
    .header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 40px 30px;
        text-align: center;
    }
    
    .header h1 {
        font-size: 2.5em;
        margin-bottom: 10px;
        font-weight: 700;
    }
    
    .header p {
        font-size: 0.95em;
        opacity: 0.95;
    }
    
    .content {
        padding: 40px;
    }
    
    .section {
        margin-bottom: 40px;
    }
    
    .section h2 {
        font-size: 1.8em;
        color: #667eea;
        margin-bottom: 20px;
        border-bottom: 3px solid #667eea;
        padding-bottom: 10px;
    }
    
    .section h3 {
        font-size: 1.2em;
        color: #764ba2;
        margin-top: 20px;
        margin-bottom: 10px;
    }
    
    .timeline {
        position: relative;
        padding: 20px 0;
    }
    
    .timeline-item {
        display: flex;
        margin-bottom: 30px;
        position: relative;
        padding-left: 40px;
    }
    
    .timeline-item::before {
        content: '';
        position: absolute;
        left: 0;
        top: 0;
        width: 20px;
        height: 20px;
        background: #667eea;
        border: 3px solid white;
        border-radius: 50%;
        box-shadow: 0 0 0 2px #667eea;
    }
    
    .timeline-item:not(:last-child)::after {
        content: '';
        position: absolute;
        left: 9px;
        top: 20px;
        bottom: -30px;
        width: 2px;
        background: #e2e8f0;
    }
    
    .timeline-item.high-risk::before {
        background: #f56565;
        box-shadow: 0 0 0 2px #f56565;
    }
    
    .timeline-content {
        flex: 1;
    }
    
    .timeline-title {
        font-weight: 600;
        color: #2d3748;
        margin-bottom: 5px;
    }
    
    .timeline-desc {
        color: #718096;
        font-size: 0.9em;
    }
    
    .detection-card {
        background: #f7fafc;
        border-left: 4px solid #667eea;
        padding: 15px;
        margin-bottom: 15px;
        border-radius: 4px;
    }
    
    .detection-card.high-risk {
        border-left-color: #f56565;
        background: #fff5f5;
    }
    
    .detection-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 10px;
        cursor: pointer;
        user-select: none;
    }
    
    .detection-header:hover {
        text-decoration: underline;
    }
    
    .technique-id {
        font-weight: 700;
        color: #667eea;
        font-size: 1.1em;
    }
    
    .detection-card.high-risk .technique-id {
        color: #f56565;
    }
    
    .technique-name {
        font-size: 0.9em;
        color: #718096;
    }
    
    .risk-badge {
        display: inline-block;
        padding: 4px 8px;
        border-radius: 12px;
        font-size: 0.75em;
        font-weight: 600;
        text-transform: uppercase;
        background: #edf2f7;
        color: #4a5568;
    }
    
    .risk-badge.high {
        background: #fed7d7;
        color: #c53030;
    }
    
    .risk-badge.medium {
        background: #feebc8;
        color: #c05621;
    }
    
    .detection-details {
        display: none;
        margin-top: 10px;
        padding-top: 10px;
        border-top: 1px solid #e2e8f0;
    }
    
    .detection-details.show {
        display: block;
    }
    
    .detail-label {
        font-weight: 600;
        color: #4a5568;
        margin-top: 8px;
        font-size: 0.85em;
        text-transform: uppercase;
    }
    
    .detail-value {
        background: white;
        padding: 10px;
        margin-top: 5px;
        border-radius: 4px;
        border: 1px solid #e2e8f0;
        font-family: 'Courier New', monospace;
        font-size: 0.85em;
        overflow-x: auto;
        color: #2d3748;
    }
    
    .kill-chain-map {
        display: flex;
        justify-content: space-between;
        gap: 10px;
        margin: 20px 0;
        flex-wrap: wrap;
    }
    
    .chain-phase {
        flex: 1;
        min-width: 140px;
        background: #f7fafc;
        border: 2px solid #e2e8f0;
        border-radius: 6px;
        padding: 12px;
        text-align: center;
        transition: all 0.3s ease;
    }
    
    .chain-phase.active {
        background: #667eea;
        color: white;
        border-color: #667eea;
        box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
    }
    
    .chain-phase-name {
        font-size: 0.8em;
        font-weight: 600;
        margin-bottom: 5px;
        text-transform: uppercase;
    }
    
    .chain-phase-techniques {
        font-size: 0.9em;
    }
    
    .command-box {
        background: #2d3748;
        color: #a0aec0;
        padding: 15px;
        border-radius: 4px;
        font-family: 'Courier New', monospace;
        font-size: 0.85em;
        overflow-x: auto;
        margin: 10px 0;
        border-left: 4px solid #667eea;
    }
    
    .command-label {
        font-size: 0.75em;
        font-weight: 700;
        color: #718096;
        text-transform: uppercase;
        margin-bottom: 8px;
        display: block;
    }
    
    .metadata {
        background: #edf2f7;
        padding: 15px;
        border-radius: 4px;
        margin-bottom: 20px;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 15px;
    }
    
    .meta-item {
        padding: 10px;
        background: white;
        border-radius: 3px;
        border-left: 3px solid #667eea;
    }
    
    .meta-label {
        font-size: 0.8em;
        font-weight: 700;
        color: #718096;
        text-transform: uppercase;
    }
    
    .meta-value {
        font-size: 1.1em;
        color: #2d3748;
        font-weight: 600;
        margin-top: 5px;
    }
    
    .footer {
        background: #edf2f7;
        padding: 20px 40px;
        text-align: center;
        color: #718096;
        font-size: 0.85em;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 15px 0;
    }
    
    th, td {
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid #e2e8f0;
    }
    
    th {
        background: #edf2f7;
        font-weight: 700;
        color: #2d3748;
    }
    
    tr:hover {
        background: #f7fafc;
    }
    
    .toggle-details {
        cursor: pointer;
        color: #667eea;
        font-size: 0.9em;
        font-weight: 600;
        margin-left: 10px;
    }
    
    .toggle-details:hover {
        text-decoration: underline;
    }
    """
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        {css}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⚔️ Command Analysis Report</h1>
            <p>MITRE ATT&CK Technique Detection & Kill Chain Mapping</p>
        </div>
        <div class="content">
"""
    return html


def _build_html_footer() -> str:
    """Build HTML closing tags and footer."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""        </div>
        <div class="footer">
            <p>Generated on {timestamp} | OD-translator Phase 4 Report</p>
        </div>
    </div>
    <script>
        document.querySelectorAll('.detection-header').forEach(header => {{
            header.addEventListener('click', function() {{
                const details = this.nextElementSibling;
                if (details && details.classList.contains('detection-details')) {{
                    details.classList.toggle('show');
                }}
            }});
        }});
    </script>
</body>
</html>"""


def _build_single_command_html(analysis: Dict[str, Any]) -> str:
    """Build HTML for single command analysis."""
    input_cmd = analysis.get("input_command", "")
    normalized_cmd = analysis.get("normalized_command", "")
    detections = analysis.get("detections", [])
    
    # Build command display section
    command_html = f"""
            <div class="section">
                <h2>📋 Command Analysis</h2>
                <span class="command-label">Input Command</span>
                <div class="command-box">{input_cmd}</div>
                <span class="command-label">Normalized Command</span>
                <div class="command-box">{normalized_cmd}</div>
            </div>
"""
    
    # Build detections section
    detections_html = """
            <div class="section">
                <h2>🎯 Detected Techniques</h2>
"""
    
    if not detections:
        detections_html += """
                <p style="color: #718096; font-style: italic;">No MITRE ATT&CK techniques detected.</p>
"""
    else:
        detections_html += f"""
                <div class="metadata">
                    <div class="meta-item">
                        <div class="meta-label">Total Detections</div>
                        <div class="meta-value">{len(detections)}</div>
                    </div>
                </div>
"""
        for det in detections:
            # Handle both flat structure (old) and nested structure (current with mitre_mapping)
            mitre = det.get("mitre_mapping", {})
            analysis = det.get("analysis", {})
            enrichment = det.get("defensive_enrichment", {})
            
            # Use subtechnique ID if available for more specificity
            subtechnique_id = mitre.get("subtechnique_id", mitre.get("technique_id", det.get("technique_id", "UNKNOWN")))
            technique_name = _resolve_display_name(mitre, det.get("technique_name", "Unknown"))
            if technique_name == subtechnique_id:
                technique_name = ""
            category = mitre.get("tactic", det.get("category", "General"))
            behavior = analysis.get("behavior", det.get("pattern", "N/A"))
            confidence = analysis.get("confidence", 0.5)
            attacker_intent = analysis.get("attacker_intent", "Unknown")
            
            # Defensive enrichment data
            telemetry = enrichment.get("telemetry_sources", [])
            detections_ops = enrichment.get("detection_opportunities", [])
            soc_notes = enrichment.get("soc_notes", "N/A")
            
            risk_level = "high" if confidence > 0.7 else "medium" if confidence > 0.4 else "low"
            risk_class = f" {risk_level}-risk" if risk_level == "high" else ""
            technique_name_html = f'<span class="technique-name">{technique_name}</span>' if technique_name else ""
            
            detections_html += f"""
                <div class="detection-card{risk_class}">
                    <div class="detection-header">
                        <div>
                            <span class="technique-id">{subtechnique_id}</span>
                            {technique_name_html}
                        </div>
                        <span class="risk-badge {risk_level}">{risk_level}</span>
                        <span class="toggle-details">[+]</span>
                    </div>
                    <div class="detection-details">
                        <div class="detail-label">Tactic</div>
                        <div class="detail-value">{category}</div>
                        <div class="detail-label">Behavior</div>
                        <div class="detail-value">{behavior}</div>
                        <div class="detail-label">Confidence</div>
                        <div class="detail-value">{confidence:.1%}</div>
                        <div class="detail-label">Attacker Intent</div>
                        <div class="detail-value">{attacker_intent}</div>
                        <div class="detail-label">SOC Notes</div>
                        <div class="detail-value">{soc_notes}</div>
                        <div class="detail-label">Telemetry Sources</div>
                        <div class="detail-value">{', '.join(telemetry) if telemetry else 'N/A'}</div>
                        <div class="detail-label">Detection Opportunities</div>
                        <div class="detail-value">{', '.join(detections_ops) if detections_ops else 'N/A'}</div>
                    </div>
                </div>
"""
    
    detections_html += """
            </div>
"""
    
    # Build kill chain mapping
    killchain_html = _build_killchain_section(detections)
    
    return command_html + detections_html + killchain_html


def _build_killchain_section(detections: List[Dict[str, Any]]) -> str:
    """Build kill chain phase visualization."""
    # Identify which phases are active
    active_phases = set()
    technique_by_phase = {}
    
    for det in detections:
        # Handle nested mitre_mapping structure
        mitre = det.get("mitre_mapping", {})
        tech_id = mitre.get("technique_id", det.get("technique_id", ""))
        # Use subtechnique ID for more specificity in display
        sub_tech_id = mitre.get("subtechnique_id", tech_id)
        
        if tech_id in KILL_CHAIN_PHASES:
            phase_num = KILL_CHAIN_PHASES[tech_id]
            active_phases.add(phase_num)
            if phase_num not in technique_by_phase:
                technique_by_phase[phase_num] = []
            technique_by_phase[phase_num].append(sub_tech_id)
    
    html = """
            <div class="section">
                <h2>🔗 Cyber Kill Chain Progression</h2>
                <div class="kill-chain-map">
"""
    
    for phase_num in sorted(range(0, 9)):
        phase_name = PHASE_NAMES.get(phase_num, "Unknown")
        is_active = phase_num in active_phases
        active_class = "active" if is_active else ""
        techs = technique_by_phase.get(phase_num, [])
        tech_display = ", ".join(techs) if techs else "-"
        
        html += f"""
                    <div class="chain-phase {active_class}">
                        <div class="chain-phase-name">{phase_name}</div>
                        <div class="chain-phase-techniques">{tech_display}</div>
                    </div>
"""
    
    html += """
                </div>
            </div>
"""
    
    return html


def _build_batch_report_html(batch_data: Dict[str, Any]) -> str:
    """Build HTML for batch analysis with timeline."""
    batch_meta = batch_data.get("batch_metadata", {})
    results = batch_data.get("results", [])
    errors = batch_data.get("error_details", [])
    
    # Metadata section
    batch_html = f"""
            <div class="section">
                <h2>📊 Batch Processing Summary</h2>
                <div class="metadata">
                    <div class="meta-item">
                        <div class="meta-label">Total Commands</div>
                        <div class="meta-value">{batch_meta.get('total', 0)}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Processed</div>
                        <div class="meta-value">{batch_meta.get('processed', 0)}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Errors</div>
                        <div class="meta-value">{batch_meta.get('errors', 0)}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Duration</div>
                        <div class="meta-value">{batch_meta.get('duration_seconds', 0)}s</div>
                    </div>
                </div>
            </div>
"""
    
    # Build execution timeline
    batch_html += """
            <div class="section">
                <h2>⏱️ Execution Timeline</h2>
                <div class="timeline">
"""
    
    for result in results:
        index = result.get("index", 0)
        analysis = result.get("result", {})
        input_cmd = analysis.get("input_command", "")
        detections = analysis.get("detections", [])
        
        # Check for high-risk detections based on confidence
        has_risk = any(det.get("analysis", {}).get("confidence", 0) > 0.7 for det in detections)
        risk_class = " high-risk" if has_risk else ""
        
        detection_summary = f"{len(detections)} detection(s)" if detections else "Clean"
        
        batch_html += f"""
                    <div class="timeline-item{risk_class}">
                        <div class="timeline-content">
                            <div class="timeline-title">Command #{index}: {detection_summary}</div>
                            <div class="timeline-desc">{input_cmd[:80]}{'...' if len(input_cmd) > 80 else ''}</div>
                        </div>
                    </div>
"""
    
    batch_html += """
                </div>
            </div>
"""
    
    # Build aggregated detection table
    all_detections = {}
    for result in results:
        analysis = result.get("result", {})
        for det in analysis.get("detections", []):
            # Handle nested mitre_mapping structure
            mitre = det.get("mitre_mapping", {})
            tech_id = mitre.get("technique_id", det.get("technique_id", ""))
            # Use subtechnique ID for more specificity
            sub_tech_id = mitre.get("subtechnique_id", tech_id)
            
            if not tech_id:
                continue
            if sub_tech_id not in all_detections:
                all_detections[sub_tech_id] = {
                    "name": _resolve_display_name(mitre, det.get("technique_name", "Unknown")),
                    "count": 0,
                    "commands": set(),
                }
            all_detections[sub_tech_id]["count"] += 1
            all_detections[sub_tech_id]["commands"].add(result.get("index", 0))
    
    if all_detections:
        batch_html += """
            <div class="section">
                <h2>📈 Aggregated Technique Coverage</h2>
                <table>
                    <tr>
                        <th>Technique ID</th>
                        <th>Name</th>
                        <th>Detections</th>
                        <th>Unique Commands</th>
                        <th>Command IDs</th>
                    </tr>
"""
        for tech_id in sorted(all_detections.keys()):
            info = all_detections[tech_id]
            unique_commands = sorted(info["commands"])
            cmds = ", ".join(map(str, unique_commands))
            batch_html += f"""
                    <tr>
                        <td><strong>{tech_id}</strong></td>
                        <td>{info['name']}</td>
                        <td>{info['count']}</td>
                        <td>{len(unique_commands)}</td>
                        <td>{cmds}</td>
                    </tr>
"""
        batch_html += """
                </table>
            </div>
"""
    
    # Error section
    if errors:
        batch_html += f"""
            <div class="section">
                <h2>⚠️ Errors ({len(errors)})</h2>
"""
        for error in errors:
            batch_html += f"""
                <div class="detection-card" style="border-left-color: #e53e3e;">
                    <div class="detail-label">Command #{error.get('index', 'N/A')}</div>
                    <div class="detail-value" style="color: #c53030;">{error.get('error', 'Unknown error')}</div>
                </div>
"""
        batch_html += """
            </div>
"""
    
    # Detailed per-command section
    batch_html += """
            <div class="section">
                <h2>🔍 Detailed Analysis Per Command</h2>
"""
    
    for result in results:
        index = result.get("index", 0)
        analysis = result.get("result", {})
        
        batch_html += f"""
                <div style="margin-bottom: 30px; padding: 15px; background: #f7fafc; border-radius: 6px;">
                    <h3>Command #{index}</h3>
                    <span class="command-label">Input</span>
                    <div class="command-box">{analysis.get('input_command', '')}</div>
"""
        
        detections = analysis.get("detections", [])
        if detections:
            batch_html += f"""
                    <div style="margin-top: 15px;">
                        <strong style="color: #667eea;">{len(detections)} Technique(s) Detected:</strong>
"""
            for det in detections:
                # Handle nested mitre_mapping structure
                mitre = det.get("mitre_mapping", {})
                analysis_data = det.get("analysis", {})
                enrichment = det.get("defensive_enrichment", {})
                
                # Use subtechnique ID for specificity
                sub_tech_id = mitre.get("subtechnique_id", mitre.get("technique_id", det.get("technique_id", "?")))
                sub_tech_name = _resolve_display_name(mitre, det.get("technique_name", "?"))
                tactic = mitre.get("tactic", "Unknown")
                confidence = analysis_data.get("confidence", 0)
                behavior = analysis_data.get("behavior", det.get("supporting_evidence", "N/A"))
                telemetry = enrichment.get("telemetry_sources", [])
                detections_ops = enrichment.get("detection_opportunities", [])
                
                batch_html += f"""
                        <div style="margin-top: 10px; padding: 15px; background: white; border-left: 3px solid #667eea; border-radius: 3px;">
                            <strong>{sub_tech_id}</strong> - {sub_tech_name}
                            <div style="font-size: 0.85em; color: #718096; margin-top: 5px;">
                                <strong>Tactic:</strong> {tactic} | <strong>Confidence:</strong> {confidence:.1%} | <strong>Behavior:</strong> {behavior}
                            </div>
                            <div style="font-size: 0.8em; color: #718096; margin-top: 8px; padding-top: 8px; border-top: 1px solid #e2e8f0;">
                                <strong>Detection Opportunities:</strong> {', '.join(detections_ops) if detections_ops else 'N/A'}
                            </div>
                            <div style="font-size: 0.8em; color: #718096; margin-top: 5px;">
                                <strong>Telemetry Sources:</strong> {', '.join(telemetry) if telemetry else 'N/A'}
                            </div>
                        </div>
"""
            batch_html += """
                    </div>
"""
        else:
            batch_html += """
                    <p style="color: #718096; font-style: italic;">No techniques detected.</p>
"""
        
        batch_html += """
                </div>
"""
    
    batch_html += """
            </div>
"""
    
    return batch_html


def generate_single_report(
    analysis: Dict[str, Any],
    output_path: Optional[str] = None,
) -> str:
    """Generate HTML report for single command analysis.
    
    Args:
        analysis: Output from translation_pipeline.translate_command()
        output_path: Optional path to save HTML file (default: data/reports/)
    
    Returns:
        HTML content as string
    """
    if output_path is None:
        output_path = "data/reports/command_analysis.html"
    
    html = _build_html_header("Command Analysis Report")
    html += _build_single_command_html(analysis)
    html += _build_html_footer()
    
    # Save to file
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    
    return html


def generate_batch_report(
    batch_data: Dict[str, Any],
    output_path: Optional[str] = None,
) -> str:
    """Generate HTML report for batch command analysis.
    
    Args:
        batch_data: Output from batch_processor.process_batch_commands()
        output_path: Optional path to save HTML file (default: data/reports/)
    
    Returns:
        HTML content as string
    """
    if output_path is None:
        output_path = "data/reports/batch_analysis.html"
    
    html = _build_html_header("Batch Analysis Report")
    html += _build_batch_report_html(batch_data)
    html += _build_html_footer()
    
    # Save to file
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    
    return html
