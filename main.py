from acl_parser import ACLParser
from conflict_detector import ConflictDetector
from report_generator import ReportGenerator
from packet_tester import PacketTester

parser = ACLParser("acl_rules.txt")
rules = parser.parse()

print(f"\nLoaded {len(rules)} rules\n")

detector = ConflictDetector(rules)
issues = detector.analyze()

# Print rules with risk scores
print("--- RULE RISK SCORES ---\n")
for rule in rules:
    print(f"  {rule} | Risk: {rule.risk_label} ({rule.risk_score}/100)")

print(f"\nFound {len(issues)} issues:\n")
for issue in issues:
    print(f"[{issue['type']}] {issue['message']}")
    print(f"  → {issue['rule1']}")
    print(f"  → {issue['rule2']}")
    print()

# Generate report
report = ReportGenerator(rules, issues)
report.generate()

# Packet Tester — interactive
print("\n" + "="*55)
print("  PACKET TESTER — Test any packet against your ACL")
print("="*55)

tester = PacketTester(rules)

while True:
    print("\nEnter packet details (or type 'exit' to quit):")
    source_ip = input("  Source IP   : ")
    if source_ip.lower() == "exit":
        break
    destination = input("  Destination : ")
    protocol = input("  Protocol    : ")
    tester.test(source_ip, destination, protocol)