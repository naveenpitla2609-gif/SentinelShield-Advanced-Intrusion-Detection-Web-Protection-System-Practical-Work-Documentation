
import json
from flask import request

from rule_engine import detect_attacks


EXCLUDED_HEADERS = {"cookie", "authorization"}

ALLOWED_METHODS = {
    "GET", "POST", "PUT", "PATCH", "DELETE"
}


def inspect_request():
    """Inspect request components and identify suspicious requests."""

    components = {
        "URL PATH": request.path,
        "HTTP METHOD": request.method,
        "QUERY PARAMETERS": "\n".join(
            f"{name}={value}"
            for name, value in request.args.items()
            if name != "component"
        ),
        "HEADERS": "\n".join(
            f"{name}: {value}"
            for name, value in request.headers.items()
            if name.lower() not in EXCLUDED_HEADERS
        ),
        "FORM DATA": "\n".join(
            f"{name}={value}"
            for name, value in request.form.items()
        ),
        "REQUEST BODY": "",
    }

    if request.is_json:
        body = request.get_json(silent=True)

        if body is not None:
            components["REQUEST BODY"] = json.dumps(
                body, ensure_ascii=False
            )
        else:
            components["REQUEST BODY"] = request.get_data(
                as_text=True, cache=True
            )

    elif not request.form:
        components["REQUEST BODY"] = request.get_data(
            as_text=True, cache=True
        )

    component_results = {}
    all_detections = []
    seen = set()

    for component_name, value in components.items():
        findings = detect_attacks(value) if value else []

        # Flag HTTP methods outside the application's allowed policy.
        if (
            component_name == "HTTP METHOD"
            and request.method not in ALLOWED_METHODS
        ):
            findings = list(findings)
            findings.append({
                "name": "UNEXPECTED_HTTP_METHOD",
                "category": "HTTP_METHOD_ANOMALY",
                "severity": "MEDIUM",
                "evidence": request.method,
            })

        component_detections = []

        for finding in findings:
            detection = {
                **finding,
                "component": component_name,
            }
            component_detections.append(detection)

            key = (
                detection.get("name"),
                component_name,
                detection.get("evidence", ""),
            )

            if key not in seen:
                seen.add(key)
                all_detections.append(detection)

        component_results[component_name] = {
            "value": value,
            "status": (
                "SUSPICIOUS" if component_detections
                else "EMPTY" if not value
                else "CLEAN"
            ),
            "detections": component_detections,
        }

    return {
        "method": request.method,
        "path": request.path,
        "component_results": component_results,
        "detections": all_detections,
        "is_malicious": bool(all_detections),
    }

