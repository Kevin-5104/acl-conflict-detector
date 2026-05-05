class ConflictDetector:
    def __init__(self, rules):
        self.rules = rules
        self.issues = []

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

    def is_subset(self, ip1, wc1, ip2, wc2):
        # Check if ip1/wc1 is a subset of ip2/wc2
        # meaning ip2/wc2 covers all IPs that ip1/wc1 covers
        if ip2 == "any" or wc2 == "any":
            return True
        if ip1 == "any":
            return False

        network1 = self.ip_to_int(ip1)
        network2 = self.ip_to_int(ip2)
        mask2 = self.wildcard_to_mask(wc2)

        # ip1 is subset of ip2/wc2 if:
        # (network1 & ~mask2) == (network2 & ~mask2)
        inverse_mask2 = 0xFFFFFFFF ^ mask2
        return (network1 & inverse_mask2) == (network2 & inverse_mask2)

    def check_redundant(self):
        for i in range(len(self.rules)):
            for j in range(i + 1, len(self.rules)):
                r1 = self.rules[i]
                r2 = self.rules[j]
                if (r1.action == r2.action and
                    r1.protocol == r2.protocol and
                    r1.source_ip == r2.source_ip and
                    r1.source_wildcard == r2.source_wildcard and
                    r1.destination == r2.destination):
                    self.issues.append({
                        "type": "REDUNDANT",
                        "rule1": r1,
                        "rule2": r2,
                        "message": f"Rule {r2.line_number} is an exact duplicate of Rule {r1.line_number}"
                    })

    def check_shadowed(self):
        for i in range(len(self.rules)):
            for j in range(i + 1, len(self.rules)):
                r1 = self.rules[i]
                r2 = self.rules[j]
                if (r1.protocol == r2.protocol and
                    r1.destination == r2.destination and
                    r1.action != r2.action and
                    self.is_subset(r2.source_ip, r2.source_wildcard,
                                   r1.source_ip, r1.source_wildcard)):
                    self.issues.append({
                        "type": "SHADOWED",
                        "rule1": r1,
                        "rule2": r2,
                        "message": f"Rule {r2.line_number} is shadowed by Rule {r1.line_number} — it will never be reached"
                    })

    def check_conflicting(self):
        for i in range(len(self.rules)):
            for j in range(i + 1, len(self.rules)):
                r1 = self.rules[i]
                r2 = self.rules[j]
                if (r1.protocol == r2.protocol and
                    r1.source_ip == r2.source_ip and
                    r1.source_wildcard == r2.source_wildcard and
                    r1.destination == r2.destination and
                    r1.action != r2.action):
                    self.issues.append({
                        "type": "CONFLICT",
                        "rule1": r1,
                        "rule2": r2,
                        "message": f"Rule {r1.line_number} and Rule {r2.line_number} directly conflict — same traffic, opposite actions"
                    })

    def analyze(self):
        self.check_redundant()
        self.check_shadowed()
        self.check_conflicting()

        # Add risk scores to all rules
        for rule in self.rules:
            rule.risk_score = self.calculate_risk_score(rule)
            rule.risk_label = self.get_risk_label(rule.risk_score)

        return self.issues
        
    def calculate_risk_score(self, rule):
        score = 0

        # Action risk
        if rule.action == "permit":
            score += 40
        else:
            score += 0

        # Source IP risk — broader the range, higher the risk
        if rule.source_ip == "any":
            score += 40
        else:
            parts = rule.source_wildcard.split(".")
            wildcard_size = int(parts[3])
            if wildcard_size == 255:
                score += 30
            elif wildcard_size >= 15:
                score += 20
            elif wildcard_size >= 1:
                score += 10
            else:
                score += 0

        # Position risk — earlier rules are riskier
        position_penalty = max(0, 20 - (rule.line_number * 3))
        score += position_penalty

        return min(score, 100)  # cap at 100

    def get_risk_label(self, score):
        if score >= 75:
            return "🔴 CRITICAL"
        elif score >= 50:
            return "🟠 HIGH"
        elif score >= 25:
            return "🟡 MEDIUM"
        else:
            return "🟢 LOW"