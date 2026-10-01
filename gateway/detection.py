# gateway/detection.py
import re
from django.core.cache import cache
from detection_rule.models import DetectionRule, RuleMatch

def get_compiled_rules():
    """Fetch active rules and return pre-compiled regex objects, cached in memory."""
    rules = cache.get("active_detection_rules")
    if rules is None:
        rules = list(DetectionRule.objects.filter(is_enabled=True))
        cache.set("active_detection_rules", rules, timeout=60)

    compiled_rules = []
    for rule in rules:
        try:
            compiled_regex = re.compile(rule.pattern, re.IGNORECASE)
            compiled_rules.append((rule, compiled_regex))
        except re.error:
            continue
    return compiled_rules


def check_anomaly_rate(client_ip, threshold=60, window=60):
    """
    Tracks request count per IP in a sliding time window (60s).
    Returns True if request count exceeds threshold.
    """
    cache_key = f"rate_limit_{client_ip}"
    request_count = cache.get(cache_key, 0) + 1
    cache.set(cache_key, request_count, timeout=window)
    return request_count > threshold, request_count


def run_detection(request_log, text_to_check, client_ip):
    total_score = 0
    matched_snippets = []
    matches_to_create = []

    compiled_rules = get_compiled_rules()

    # --- 1. Signature & Keyword Regex Checks ---
    for rule, compiled_regex in compiled_rules:
        if rule.rule_type in ["signature", "keyword"]:
            match = compiled_regex.search(text_to_check)
            if match:
                matched_val = match.group()
                matches_to_create.append(
                    RuleMatch(
                        request_log=request_log,
                        rule=rule,
                        matched_value=f"[{rule.rule_type.upper()}] {matched_val}",
                        points_awarded=rule.risk_weight,
                    )
                )
                total_score += rule.risk_weight
                matched_snippets.append(matched_val)

        # --- 2. Anomaly Rule Checks ---
        elif rule.rule_type == "anomaly":
            # Example: Rate limit anomaly rule
            if "RATE_EXCEEDED" in rule.pattern:
                is_exceeded, count = check_anomaly_rate(client_ip, threshold=60)
                if is_exceeded:
                    matches_to_create.append(
                        RuleMatch(
                            request_log=request_log,
                            rule=rule,
                            matched_value=f"[ANOMALY] High request rate ({count} req/min)",
                            points_awarded=rule.risk_weight,
                        )
                    )
                    total_score += rule.risk_weight
                    matched_snippets.append(f"Rate Anomaly ({count} req/min)")

    if matches_to_create:
        RuleMatch.objects.bulk_create(matches_to_create)

    request_log.payload_snippet = "; ".join(matched_snippets)
    return total_score