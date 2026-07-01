def generate_report(results, output_file="audit_report.txt"):
    """
    Creates a plain-English firewall audit report and saves it to a text file.
    """

    risk_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "SAFE": 0,
        "REVIEW": 0
    }

    for result in results:
        risk = result["risk"]
        if risk in risk_counts:
            risk_counts[risk] += 1

    with open(output_file, "w") as file:
        file.write("Firewall Rule Risk Audit Report\n")
        file.write("=" * 40 + "\n\n")

        file.write("Summary\n")
        file.write("-" * 40 + "\n")
        file.write(f"Total Rules Scanned: {len(results)}\n")
        file.write(f"High Risk Rules: {risk_counts['HIGH']}\n")
        file.write(f"Medium Risk Rules: {risk_counts['MEDIUM']}\n")
        file.write(f"Low Risk Rules: {risk_counts['LOW']}\n")
        file.write(f"Safe Rules: {risk_counts['SAFE']}\n")
        file.write(f"Needs Review: {risk_counts['REVIEW']}\n\n")

        file.write("Detailed Findings\n")
        file.write("-" * 40 + "\n\n")

        for index, result in enumerate(results, start=1):
            rule = result["rule"]

            file.write(f"Finding #{index}\n")
            file.write(f"Rule: {rule['action']} {rule['protocol']} {rule['port']} FROM {rule['source']}\n")
            file.write(f"Service: {result['service']}\n")
            file.write(f"Risk: {result['risk']}\n")
            file.write(f"Reason: {result['reason']}\n")
            file.write(f"Recommendation: {result['recommendation']}\n")
            file.write("\n")

    return output_file