from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import requests
import streamlit as st


APP_NAME = "SentinelAI"
TAGLINE = "The Zero-Trust Firewall for Corporate GenAI Workflows."
REQUEST_TIMEOUT_SECONDS = 15


class GatewayAPIError(RuntimeError):
    """A readable error returned when the configured gateway API is unavailable."""


def get_api_base_url() -> str:
    """Read the backend URL from Streamlit secrets or environment variables."""
    secret_url = ""
    try:
        secret_url = str(st.secrets.get("API_BASE_URL", "") or "").strip()
    except Exception:
        # No secrets file is normal during local development.
        secret_url = ""
    env_url = os.getenv("API_BASE_URL", "").strip()
    base_url = (secret_url or env_url).rstrip("/")
    # Accept either the backend origin or an origin ending in /api.
    if base_url.endswith("/api"):
        base_url = base_url[:-4].rstrip("/")
    return base_url


def api_request(method: str, path: str, **kwargs: Any) -> Any:
    base_url = get_api_base_url()
    if not base_url:
        raise GatewayAPIError(
            "Backend URL is not configured. In Streamlit Community Cloud, open "
            "App settings → Secrets and add API_BASE_URL = \"https://your-backend-host\". "
            "For local development, set API_BASE_URL in your environment."
        )

    url = f"{base_url}/api{path}"
    try:
        response = requests.request(
            method,
            url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            headers={"Accept": "application/json"},
            **kwargs,
        )
    except requests.RequestException as exc:
        raise GatewayAPIError(
            "Could not reach the FastAPI backend. Confirm that it is deployed and reachable "
            "over HTTPS, then check the API_BASE_URL secret."
        ) from exc

    if not response.ok:
        detail = response.text.strip()
        try:
            payload = response.json()
            if isinstance(payload, dict):
                detail = str(payload.get("detail") or detail)
        except ValueError:
            pass
        raise GatewayAPIError(detail or f"Backend request failed with HTTP {response.status_code}.")

    try:
        return response.json()
    except ValueError as exc:
        raise GatewayAPIError("The backend returned a response that was not valid JSON.") from exc


def get_json(path: str) -> Any:
    return api_request("GET", path)


def post_json(path: str, payload: Dict[str, Any]) -> Any:
    return api_request("POST", path, json=payload)


def show_api_error(exc: Exception) -> None:
    st.error(str(exc))


def action_label(action: str) -> str:
    labels = {
        "ALLOW": "Request allowed",
        "MASK": "Sensitive data masked",
        "BLOCK": "Request blocked",
    }
    return labels.get(str(action).upper(), str(action).replace("_", " ").title())


def render_header(title: str, subtitle: str) -> None:
    left, right = st.columns([0.76, 0.24], vertical_alignment="center")
    with left:
        st.markdown(f"<div class='eyebrow'>{APP_NAME} / SECURITY OPERATIONS</div>", unsafe_allow_html=True)
        st.title(title)
        st.caption(subtitle)
    with right:
        try:
            health = get_json("/health")
            if str(health.get("status", "")).lower() == "healthy":
                st.markdown("<div class='status-pill status-ok'><span></span> Gateway reachable</div>", unsafe_allow_html=True)
            else:
                st.markdown("<div class='status-pill status-warn'><span></span> Check gateway status</div>", unsafe_allow_html=True)
        except Exception:
            st.markdown("<div class='status-pill status-off'><span></span> API not connected</div>", unsafe_allow_html=True)


def fetch_metrics_and_logs() -> tuple[Optional[Dict[str, Any]], Optional[List[Dict[str, Any]]], Optional[str]]:
    try:
        metrics = get_json("/logs/metrics")
        logs = get_json("/logs?limit=50")
        return metrics, logs, None
    except Exception as exc:
        return None, None, str(exc)


def render_dashboard() -> None:
    render_header("Security overview", "A concise view of gateway activity and recent security decisions.")
    metrics, logs, error = fetch_metrics_and_logs()
    if error:
        st.warning("Live dashboard data is unavailable until the backend is configured and reachable.")
        st.code(error, language=None)
        metrics = {"total_requests": 0, "blocked_count": 0, "masked_count": 0, "allowed_count": 0, "leak_type_distribution": {}}
        logs = []

    metrics = metrics or {}
    total = int(metrics.get("total_requests", 0) or 0)
    blocked = int(metrics.get("blocked_count", 0) or 0)
    masked = int(metrics.get("masked_count", 0) or 0)
    allowed = int(metrics.get("allowed_count", 0) or 0)

    metric_cols = st.columns(4)
    metric_cols[0].metric("Requests scanned", f"{total:,}")
    metric_cols[1].metric("Threats blocked", f"{blocked:,}")
    metric_cols[2].metric("Requests masked", f"{masked:,}")
    metric_cols[3].metric("Requests allowed", f"{allowed:,}")
    st.caption("Metrics are returned by the backend. The current backend uses in-memory logs, which can reset when its process restarts.")

    st.markdown("### Recent incidents")
    if not logs:
        st.info("No audit events have been returned yet. Submit a prompt in Gateway Playground to generate a real event.")
    else:
        rows = []
        for item in logs[:10]:
            rows.append({
                "Time (UTC)": str(item.get("timestamp", "" )).replace("T", " ").replace("Z", ""),
                "Action": item.get("action", "—"),
                "Risk": f"{float(item.get('risk_score', 0) or 0):.0%}",
                "Signals": ", ".join(item.get("detected_types") or []) or "—",
                "Role": item.get("user_role", "—"),
                "Sanitized preview": item.get("sanitized_preview", "—"),
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)

    distribution = metrics.get("leak_type_distribution") or {}
    if distribution:
        st.markdown("### Detected categories")
        category_rows = [{"Category": name, "Events": count} for name, count in sorted(distribution.items(), key=lambda pair: pair[1], reverse=True)]
        st.dataframe(category_rows, use_container_width=True, hide_index=True)


def render_gateway_playground() -> None:
    render_header("Gateway playground", "Submit a prompt and inspect the actual decision returned by the security gateway.")
    st.markdown(
        "<div class='callout'>Prompts entered here are sent to your configured FastAPI gateway. "
        "Use synthetic examples only; do not enter real passwords, credentials, or personal information.</div>",
        unsafe_allow_html=True,
    )

    left, right = st.columns([1, 1], gap="large")
    with left:
        st.markdown("### 01 / Prompt input")
        with st.form("gateway_scan_form", clear_on_submit=False):
            prompt = st.text_area(
                "Prompt to inspect",
                key="gateway_prompt",
                height=180,
                placeholder="Example: Please summarize this note for the engineering team.",
                help="The gateway inspects the prompt before forwarding a sanitized version to its configured model service.",
            )
            st.markdown("#### User context")
            role = st.selectbox("User role", ["intern", "general", "engineer", "admin"], index=1)
            department = st.selectbox("Department", ["engineering", "finance", "human_resources", "legal", "operations"], index=0)
            st.markdown("#### Optional document access check")
            doc_id = st.text_input("Document ID (leave blank to skip)", placeholder="e.g. FIN-RESTRICTED-001")
            doc_title = st.text_input("Document title", placeholder="e.g. Restricted finance report")
            clearance = st.selectbox("Required clearance", ["public", "internal", "confidential", "restricted"], index=0)
            submitted = st.form_submit_button("Inspect prompt", type="primary", use_container_width=True)

    with right:
        st.markdown("### 02 / Gateway inspection")
        if submitted:
            if not prompt.strip():
                st.warning("Enter a prompt before starting an inspection.")
            else:
                payload: Dict[str, Any] = {
                    "prompt": prompt,
                    "user_context": {
                        "user_id": "streamlit_demo_user",
                        "role": role,
                        "department": department,
                    },
                    "document_context": None,
                }
                if doc_id.strip():
                    payload["document_context"] = {
                        "doc_id": doc_id.strip(),
                        "title": doc_title.strip() or doc_id.strip(),
                        "required_clearance": clearance,
                    }
                start = time.perf_counter()
                try:
                    result = post_json("/gateway/scan", payload)
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    st.session_state["last_scan_result"] = result
                    st.session_state["last_scan_elapsed_ms"] = elapsed_ms
                except Exception as exc:
                    st.session_state.pop("last_scan_result", None)
                    st.session_state.pop("last_scan_elapsed_ms", None)
                    show_api_error(exc)

        result = st.session_state.get("last_scan_result")
        if not result:
            st.markdown(
                "<div class='inspection-placeholder'><div class='inspection-index'>WAITING FOR REQUEST</div>"
                "<h3>Inspection result will appear here</h3><p>Submit a synthetic prompt to view the gateway's live response.</p>"
                "<div class='flow-row'><span>Input scanned</span><span>Policy evaluated</span><span>Decision returned</span></div></div>",
                unsafe_allow_html=True,
            )
        else:
            action = str(result.get("action", "UNKNOWN")).upper()
            if action == "BLOCK":
                st.error(f"{action_label(action)}")
            elif action == "MASK":
                st.warning(f"{action_label(action)}")
            else:
                st.success(f"{action_label(action)}")

            elapsed = st.session_state.get("last_scan_elapsed_ms")
            if elapsed is not None:
                st.caption(f"API round-trip: {elapsed:.0f} ms · Includes network time; not gateway-only overhead.")
            score = max(0.0, min(1.0, float(result.get("risk_score", 0) or 0)))
            st.metric("Risk score", f"{score:.0%}")
            st.progress(score)

            st.markdown("#### Inspection path")
            st.markdown("- Input scanned")
            entities = result.get("entities_detected") or []
            if entities:
                labels = sorted({str(entity.get("label") or entity.get("entity_type") or "Sensitive data") for entity in entities})
                st.markdown("- Sensitive data detected: " + ", ".join(f"`{label}`" for label in labels))
            if result.get("injection_detected"):
                st.markdown("- `Prompt injection detected`")
            if result.get("permission_granted") is False:
                st.markdown("- `Document access denied`")
            elif doc_id.strip():
                st.markdown("- Document permission check passed")
            st.markdown(f"- **Decision:** {action}")

            if result.get("blocked_reason"):
                st.info(str(result["blocked_reason"]))
            st.markdown("#### Sanitized prompt")
            st.code(str(result.get("sanitized_prompt", "")), language=None)
            if result.get("llm_response"):
                st.markdown("#### Model response")
                st.write(str(result["llm_response"]))
            if entities:
                st.markdown("#### Findings")
                finding_rows = [{
                    "Type": entity.get("entity_type", "—"),
                    "Label": entity.get("label", "—"),
                    "Severity": entity.get("severity", "—"),
                } for entity in entities]
                st.dataframe(finding_rows, use_container_width=True, hide_index=True)

    st.divider()
    st.caption("The current backend uses a mock LLM by default. Document authorization checks use the document metadata supplied with the request; this is not a full RAG document store.")


def render_audit_trail() -> None:
    render_header("Audit trail", "Review recorded gateway decisions and sanitized event metadata.")
    try:
        logs = get_json("/logs?limit=100")
    except Exception as exc:
        show_api_error(exc)
        return

    if not logs:
        st.info("No audit records found. Run a prompt inspection first.")
        return

    filter_col, search_col = st.columns([0.28, 0.72])
    with filter_col:
        action_filter = st.selectbox("Action", ["All", "ALLOW", "MASK", "BLOCK"])
    with search_col:
        search = st.text_input("Search metadata", placeholder="Search type, role, reason, or sanitized preview")

    filtered = []
    search_lower = search.lower().strip()
    for item in logs:
        if action_filter != "All" and str(item.get("action", "")).upper() != action_filter:
            continue
        searchable = " ".join([
            str(item.get("id", "")), str(item.get("user_role", "")),
            str(item.get("blocked_reason", "")), str(item.get("sanitized_preview", "")),
            " ".join(item.get("detected_types") or []),
        ]).lower()
        if search_lower and search_lower not in searchable:
            continue
        filtered.append(item)

    st.caption(f"Showing {len(filtered)} of {len(logs)} records returned by the backend.")
    rows = [{
        "Event ID": item.get("id", "—"),
        "Timestamp (UTC)": str(item.get("timestamp", "")).replace("T", " ").replace("Z", ""),
        "Action": item.get("action", "—"),
        "Risk": f"{float(item.get('risk_score', 0) or 0):.0%}",
        "Detected types": ", ".join(item.get("detected_types") or []) or "—",
        "User role": item.get("user_role", "—"),
        "Sanitized preview": item.get("sanitized_preview", "—"),
        "Reason": item.get("blocked_reason") or "—",
    } for item in filtered]
    if rows:
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("No audit records match these filters.")
    st.caption("The backend response exposes sanitized previews and metadata. Log persistence depends on the backend's current in-memory storage implementation.")


def render_policy_center() -> None:
    render_header("Policy center", "Configure the security controls exposed by the existing gateway API.")
    try:
        current = get_json("/rules")
    except Exception as exc:
        show_api_error(exc)
        return

    st.markdown("### Active controls")
    st.caption("These controls are loaded from and saved to the backend. The backend currently stores policy settings in memory.")
    with st.form("policy_settings_form"):
        block_injection = st.checkbox("Block prompt-injection attempts", value=bool(current.get("block_on_injection", True)), help="Block requests flagged by the backend's prompt-injection detector.")
        block_secrets = st.checkbox("Block high-risk secrets and credentials", value=bool(current.get("block_on_secrets", True)), help="Block requests when the backend detects high- or critical-severity entities.")
        mask_pii = st.checkbox("Mask detected personal information", value=bool(current.get("mask_pii", True)), help="Mask detected entities when the policy engine permits masking.")
        enforce_permissions = st.checkbox("Enforce document clearance checks", value=bool(current.get("enforce_document_permissions", True)), help="Apply the backend's role-versus-clearance check when a document ID is supplied.")
        save = st.form_submit_button("Save policy settings", type="primary")

    if save:
        payload = {
            "block_on_injection": block_injection,
            "block_on_secrets": block_secrets,
            "mask_pii": mask_pii,
            "enforce_document_permissions": enforce_permissions,
        }
        try:
            saved = post_json("/rules", payload)
            st.success("Policy settings saved by the backend.")
            st.json(saved)
        except Exception as exc:
            show_api_error(exc)

    st.markdown("### Enforcement sequence")
    st.markdown(
        "1. Check document clearance when document metadata is supplied.\n"
        "2. Inspect the prompt for injection patterns.\n"
        "3. Detect sensitive entities and credentials.\n"
        "4. Apply the configured allow, mask, or block policy.\n"
        "5. Return a sanitized prompt and record audit metadata."
    )


def render_system_health() -> None:
    render_header("System health", "Check API connectivity and understand the current deployment boundaries.")
    base_url = get_api_base_url()
    st.markdown("### Backend connection")
    st.code(base_url if base_url else "API_BASE_URL is not configured", language=None)
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Check connection", type="primary", use_container_width=True):
            try:
                health = get_json("/health")
                st.success("Backend responded successfully.")
                st.json(health)
            except Exception as exc:
                show_api_error(exc)
    with col2:
        st.link_button("Open API documentation", f"{base_url}/docs" if base_url else "https://docs.streamlit.io/", use_container_width=True, disabled=not bool(base_url))

    st.markdown("### Deployment checklist")
    st.markdown(
        "- Streamlit app is hosted on Streamlit Community Cloud.\n"
        "- FastAPI backend is hosted separately at a public HTTPS URL.\n"
        "- `API_BASE_URL` is configured in Streamlit app Secrets.\n"
        "- Backend is reachable from the public internet.\n"
        "- Use synthetic data during demonstrations.\n"
        "- The current backend uses a mock LLM and in-memory audit/policy storage."
    )


def main() -> None:
    st.set_page_config(page_title=f"{APP_NAME} | AI Security Gateway", page_icon="A", layout="wide", initial_sidebar_state="expanded")
    st.markdown(
        """
        <style>
        :root { color-scheme: dark; }
        .stApp { background: #0D1117; }
        [data-testid="stHeader"] { background: rgba(13, 17, 23, 0.92); }
        [data-testid="stSidebar"] { background: #10151c; border-right: 1px solid #292f38; }
        [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 { letter-spacing: -0.03em; }
        h1, h2, h3 { letter-spacing: -0.035em; }
        h1 { font-weight: 650 !important; }
        .eyebrow { color: #9299a6; font-size: 0.70rem; letter-spacing: .13em; font-weight: 650; margin-bottom: .45rem; }
        .status-pill { display: inline-flex; align-items: center; gap: .5rem; padding: .45rem .7rem; border: 1px solid #343c46; border-radius: 999px; font-size: .78rem; color: #d7d9dd; margin-top: .75rem; white-space: nowrap; }
        .status-pill span { width: 7px; height: 7px; border-radius: 50%; background: #8bb69a; display: inline-block; }
        .status-warn span { background: #c7ad78; } .status-off span { background: #c78e8e; }
        .callout { border: 1px solid #333b46; border-left: 3px solid #8b95b7; border-radius: 7px; padding: .85rem 1rem; color: #c5cad2; background: #121821; margin-bottom: 1.1rem; font-size: .9rem; }
        .inspection-placeholder { border: 1px dashed #3a424d; border-radius: 9px; padding: 1.5rem; min-height: 280px; background: #10151c; }
        .inspection-index { font-size: .67rem; color: #969eac; letter-spacing: .13em; font-weight: 700; }
        .inspection-placeholder h3 { margin-top: 1.1rem; font-size: 1.2rem; }
        .inspection-placeholder p { color: #9da5b1; font-size: .9rem; }
        .flow-row { display: flex; flex-wrap: wrap; gap: .4rem; margin-top: 2rem; }
        .flow-row span { border: 1px solid #343c46; background: #171e27; color: #c1c7d0; border-radius: 5px; padding: .35rem .5rem; font-size: .72rem; }
        div[data-testid="stMetric"] { background: transparent; border: 0; border-top: 1px solid #333b45; padding: .8rem .2rem .5rem 0; }
        div[data-testid="stMetricLabel"] { color: #9da5b1; font-size: .82rem; }
        div[data-testid="stMetricValue"] { font-weight: 650; letter-spacing: -.04em; }
        div[data-testid="stForm"] { border: 1px solid #303741; border-radius: 9px; padding: 1rem; background: #10151c; }
        .stButton > button, .stFormSubmitButton > button { border-radius: 6px; font-weight: 600; }
        div[data-testid="stDataFrame"] { border: 1px solid #2e3540; border-radius: 8px; overflow: hidden; }
        hr { border-color: #2a3039; }
        code { border-radius: 4px; }
        @media (max-width: 720px) { .status-pill { margin-top: 0; } }
        </style>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.markdown("# SentinelAI")
        st.caption("THE ZERO-TRUST FIREWALL FOR CORPORATE GENAI WORKFLOWS")
        st.divider()
        page = st.radio(
            "Workspace",
            ["Security overview", "Gateway playground", "Audit trail", "Policy center", "System health"],
            label_visibility="collapsed",
        )
        st.divider()
        st.caption("API status is checked when each page loads. This UI calls the existing FastAPI service; detection and enforcement remain in the backend.")

    if page == "Security overview":
        render_dashboard()
    elif page == "Gateway playground":
        render_gateway_playground()
    elif page == "Audit trail":
        render_audit_trail()
    elif page == "Policy center":
        render_policy_center()
    else:
        render_system_health()


if __name__ == "__main__":
    main()
