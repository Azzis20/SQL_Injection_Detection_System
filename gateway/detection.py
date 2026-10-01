import re
from django.core.cache import cache
from detection_rule.models import DetectionRule, RuleMatch

def get_compiled_rules():
    """Fetch active rules and return pre-compiled regex objects, cached in memory."""
    rules = cache.get("active_detection_rules")
    if rules is None:
        rules = list(DetectionRule.objects.filter(is_enabled=True))
        # Cache for 60 seconds (or invalidate via signal when rules change)
        cache.set("active_detection_rules", rules, timeout=60)

    compiled_rules = []
    for rule in rules:
        try:
            compiled_regex = re.compile(rule.pattern, re.IGNORECASE)
            compiled_rules.append((rule, compiled_regex))
        except re.error:
            continue
    return compiled_rules


def run_detection(request_log, text_to_check):
    total_score = 0
    matched_snippets = []
    matches_to_create = []

    compiled_rules = get_compiled_rules()

    for rule, compiled_regex in compiled_rules:
        match = compiled_regex.search(text_to_check)
        if match:
            matched_val = match.group()
            matches_to_create.append(
                RuleMatch(
                    request_log=request_log,
                    rule=rule,
                    matched_value=matched_val,
                    points_awarded=rule.risk_weight,
                )
            )
            total_score += rule.risk_weight
            matched_snippets.append(matched_val)

    # Bulk create database entries for triggered rules to avoid multiple DB round-trips
    if matches_to_create:
        RuleMatch.objects.bulk_create(matches_to_create)

    request_log.payload_snippet = "; ".join(matched_snippets)
    return total_score