from parser import load_rules
from risk_engine import analyze_rule
from reporter import generate_report


def main():
    rules = load_rules("sample_rules.txt")
    results = []

    for rule in rules:
        result = analyze_rule(rule)
        results.append(result)

    report_file = generate_report(results)

    print("Firewall Rule Risk Auditor")
    print("-" * 40)
    print(f"Total rules scanned: {len(results)}")
    print(f"Report saved to: {report_file}")


if __name__ == "__main__":
    main()