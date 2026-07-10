from flask import Flask, render_template, request
from parser import parse_rule
from risk_engine import analyze_rule

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    summary = {
        "total": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "SAFE": 0,
        "REVIEW": 0,
        "INVALID": 0
    }

    sample_input = """ALLOW TCP 22 FROM 0.0.0.0/0
ALLOW TCP 443 FROM 0.0.0.0/0
ALLOW TCP 3306 FROM 0.0.0.0/0
DENY TCP 23 FROM 0.0.0.0/0"""

    user_input = sample_input

    if request.method == "POST":
        user_input = request.form.get("rules", "")

        for line in user_input.splitlines():
            if not line.strip():
                continue

            parsed_rule = parse_rule(line)

            if parsed_rule is None:
                results.append({
                    "rule_text": line,
                    "service": "Unknown",
                    "risk": "INVALID",
                    "reason": "This rule does not match the required format.",
                    "recommendation": "Use this format: ALLOW TCP 22 FROM 0.0.0.0/0"
                })
                summary["INVALID"] += 1
                continue

            result = analyze_rule(parsed_rule)
            result["rule_text"] = f"{parsed_rule['action']} {parsed_rule['protocol']} {parsed_rule['port']} FROM {parsed_rule['source']}"
            results.append(result)

            risk = result["risk"]
            if risk in summary:
                summary[risk] += 1

        summary["total"] = len(results)

    return render_template(
        "index.html",
        results=results,
        summary=summary,
        user_input=user_input
    )


if __name__ == "__main__":
    app.run(debug=True)