def parse_rule(line):
    """
    Converts one firewall rule line into a structured dictionary.

    Expected format:
    ALLOW TCP 22 FROM 0.0.0.0/0
    """

    parts = line.strip().split() # Made an array

    if len(parts) != 5 or parts[3].upper() != "FROM":
        return None

    action = parts[0].upper()
    protocol = parts[1].upper()
    port = int(parts[2])
    source = parts[4]

    return {
        "action": action,
        "protocol": protocol,
        "port": port,
        "source": source
    }


def load_rules(filename):
    """
    Reads all firewall rules from a file and parses them.
    """

    rules = []

    with open(filename, "r") as file:
        for line in file:
            if line.strip():
                parsed_rule = parse_rule(line)

                if parsed_rule:
                    rules.append(parsed_rule)

    return rules