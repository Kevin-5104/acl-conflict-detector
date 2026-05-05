class Rule:
    def __init__(self, line_number, action, protocol, source_ip, source_wildcard, destination):
        self.line_number = line_number
        self.action = action.lower()           # permit or deny
        self.protocol = protocol.lower()       # ip, tcp, udp, icmp
        self.source_ip = source_ip             # e.g. 192.168.1.0
        self.source_wildcard = source_wildcard # e.g. 0.0.0.255
        self.destination = destination         # any or specific IP

    def __str__(self):
        return (f"Rule {self.line_number}: {self.action.upper()} {self.protocol} "
                f"{self.source_ip} {self.source_wildcard} {self.destination}")