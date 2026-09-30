# gateway/detection.py
import re
# from attack_logs.models import DetectionRule, RuleMatch
from detection_rule.models import DetectionRule, RuleMatch

def run_detection(request_log, text_to_check):
    """
    Checks the given text against all enabled DetectionRules,
    creates a RuleMatch for each hit, and returns the total risk score.
    """
    total_score = 0
    active_rules = DetectionRule.objects.filter(is_enabled=True)

    for rule in active_rules:
        match = re.search(rule.pattern, text_to_check, re.IGNORECASE)
        if match:
            RuleMatch.objects.create(
                request_log=request_log,
                rule=rule,
                matched_value=match.group(),
                points_awarded=rule.risk_weight,
            )
            total_score += rule.risk_weight

    return total_score