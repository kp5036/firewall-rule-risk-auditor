COMMON_PORTS = {
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    3389: "Remote Desktop Protocol",
    6379: "Redis",
    8080: "HTTP Alternate"
}

HIGH_RISK_PUBLIC_PORTS = {
    22,
    23,
    3306,
    5432,
    3389,
    6379,
    27017
}


def is_public_source(source):
    """
    Checks if the firewall rule is open to the public internet.
    """

    return source == "0.0.0.0/0"


def analyze_rule(rule):
    """
    Analyzes one parsed firewall rule and returns risk details.
    """

    action = rule["action"]
    port = rule["port"]
    source = rule["source"]
    service = COMMON_PORTS.get(port, "Unknown Service")

    if action == "DENY":
        return {
            "rule": rule,
            "service": service,
            "risk": "SAFE",
            "reason": "This rule denies traffic, so it does not expose the service.",
            "recommendation": "No immediate action required."
        }

    if is_public_source(source) and port in HIGH_RISK_PUBLIC_PORTS:
        return {
            "rule": rule,
            "service": service,
            "risk": "HIGH",
            "reason": f"{service} is exposed to the public internet.",
            "recommendation": "Restrict access to trusted IP addresses or private network ranges."
        }

    if is_public_source(source) and port in {80, 443}:
        return {
            "rule": rule,
            "service": service,
            "risk": "LOW",
            "reason": f"{service} is publicly exposed, which is common for web services.",
            "recommendation": "Confirm this service is intentionally public and protected with proper security controls."
        }

    if not is_public_source(source):
        return {
            "rule": rule,
            "service": service,
            "risk": "MEDIUM",
            "reason": f"{service} is restricted to a non-public source range.",
            "recommendation": "Verify that the source range follows least-privilege access."
        }

    return {
        "rule": rule,
        "service": service,
        "risk": "REVIEW",
        "reason": "This rule does not match a known risk pattern.",
        "recommendation": "Review the rule manually."
    }