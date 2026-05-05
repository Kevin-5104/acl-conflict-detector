class PacketTester:
    def __init__(self, rules):
        self.rules = rules

    def ip_to_int(self, ip):
        parts = ip.split(".")
        result = 0
        for part in parts:
            result = result * 256 + int(part)
        return result

    def wildcard_to_mask(self, wildcard):
        parts = wildcard.split(".")
        result = 0
        for part in parts:
            result = result * 256 + int(part)
        return result

    def ip_matches_rule(self, packet_ip, rule_ip, rule_wildcard):
        if rule_ip == "any":
            return True
        pkt = self.ip_to_int(packet_ip)
        net = self.ip_to_int(rule_ip)
        mask = self.wildcard_to_mask(rule_wildcard)
        inverse_mask = 0xFFFFFFFF ^ mask
        return (pkt & inverse_mask) == (net & inverse_mask)

    def test(self, source_ip, destination, protocol):
        print(f"\n{'='*55}")
        print(f"  PACKET TEST")
        print(f"  Source IP   : {source_ip}")
        print(f"  Destination : {destination}")
        print(f"  Protocol    : {protocol}")
        print(f"{'='*55}\n")

        for rule in self.rules:
            # Check protocol match
            if rule.protocol != "ip" and rule.protocol != protocol:
                print(f"  Rule {rule.line_number} — SKIPPED (protocol mismatch)")
                continue

            # Check source IP match
            if self.ip_matches_rule(source_ip, rule.source_ip, rule.source_wildcard):
                print(f"  Rule {rule.line_number} — MATCHED ✅")
                print(f"  → {rule}")
                print(f"  → Risk: {rule.risk_label} ({rule.risk_score}/100)")
                if rule.action == "permit":
                    print(f"\n  DECISION: ✅ PACKET PERMITTED")
                else:
                    print(f"\n  DECISION: ❌ PACKET DENIED")
                print(f"{'='*55}\n")
                return
            else:
                print(f"  Rule {rule.line_number} — no match, checking next...")

        print(f"\n  DECISION: ❌ PACKET DENIED — implicit deny at end of ACL")
        print(f"{'='*55}\n")