import datetime

class ReportGenerator:
    def __init__(self, rules, issues):
        self.rules = rules
        self.issues = issues

    def generate(self):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        filename = f"acl_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        lines = []
        lines.append("=" * 60)
        lines.append("  FIREWALL ACL CONFLICT DETECTION REPORT")
        lines.append(f"  Generated On : {now}")
        lines.append(f"  Total Rules  : {len(self.rules)}")
        lines.append(f"  Total Issues : {len(self.issues)}")
        lines.append("=" * 60)

        lines.append("\n--- ALL RULES WITH RISK SCORES ---\n")
        for rule in self.rules:
            lines.append(f"  {rule} | Risk: {rule.risk_label} ({rule.risk_score}/100)")

        lines.append("\n--- DETECTED ISSUES ---\n")

        if not self.issues:
            lines.append("  No issues found. ACL is clean.")
        else:
            for issue in self.issues:
                lines.append(f"  [{issue['type']}] {issue['message']}")
                lines.append(f"    -> {issue['rule1']}")
                lines.append(f"    -> {issue['rule2']}")
                lines.append("")

        lines.append("=" * 60)
        lines.append("  END OF REPORT")
        lines.append("=" * 60)

        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        print(f"\n Report saved -> {filename}")
        return filename