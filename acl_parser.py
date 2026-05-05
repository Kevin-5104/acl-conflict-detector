from rule import Rule

class ACLParser:
    def __init__(self, filename):
        self.filename = filename
        self.rules = []

    def parse(self):
        with open(self.filename, "r") as f:
            lines = f.readlines()

        for index, line in enumerate(lines):
            line = line.strip()
            if line == "" or line.startswith("#"):
                continue

            parts = line.split()

            # Handle "deny ip any any" — 4 parts
            if len(parts) == 4 and parts[3] == "any":
                parts.append("any")

            if len(parts) != 5:
                print(f"Skipping invalid rule at line {index + 1}: {line}")
                continue

            action = parts[0]
            protocol = parts[1]
            source_ip = parts[2]
            source_wildcard = parts[3]
            destination = parts[4]

            rule = Rule(index + 1, action, protocol, source_ip, source_wildcard, destination)
            self.rules.append(rule)

        return self.rules