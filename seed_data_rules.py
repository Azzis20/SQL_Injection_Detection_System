"""
Seeds admin user accounts and detection rules. Safe to run on every deploy --
uses get_or_create() throughout, so re-running never creates duplicates or
overwrites data that already exists.

Run with:
    python manage.py shell -c "exec(open('seed_data.py').read())"

Or add directly to build.sh so it runs automatically on every deploy:
    python manage.py shell -c "exec(open('seed_data.py').read())"
"""
import os
import secrets
from django.contrib.auth.models import User
from detection_rule.models import DetectionRule


# ---------------------------------------------------------------------------
# 1. Admin user accounts
# ---------------------------------------------------------------------------
# Real login passwords are read from environment variables, never hardcoded
# here -- this file is committed to a public repo, so a literal password
# would be visible to anyone who looks at the source.

def create_user_if_missing(username, email, password, is_staff, is_superuser):
    user, created = User.objects.get_or_create(
        username=username,
        defaults={
            "email": email,
            "is_staff": is_staff,
            "is_superuser": is_superuser,
            "is_active": True,
        },
    )
    if created:
        user.set_password(password)   # hashes it properly, never stored in plain text
        user.save()
    return created


# --- Primary admin: the one you actually log in as during your demo ---
ADMIN_USERNAME = os.environ.get("DJANGO_ADMIN_USERNAME", "admin")
ADMIN_EMAIL = os.environ.get("DJANGO_ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("DJANGO_ADMIN_PASSWORD")

if ADMIN_PASSWORD:
    created = create_user_if_missing(ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD, True, True)
    print(f"{'Created' if created else 'Already exists, skipped'} superuser: {ADMIN_USERNAME}")
else:
    print(
        "WARNING: DJANGO_ADMIN_PASSWORD not set -- skipped admin user creation. "
        "Set it in Render's environment variables to auto-create a login."
    )

# --- Secondary superuser (admin2): same pattern, own env var ---
ADMIN2_USERNAME = os.environ.get("DJANGO_ADMIN2_USERNAME", "admin2")
ADMIN2_EMAIL = os.environ.get("DJANGO_ADMIN2_EMAIL", "admin2@example.com")
ADMIN2_PASSWORD = os.environ.get("DJANGO_ADMIN2_PASSWORD")

if ADMIN2_PASSWORD:
    created = create_user_if_missing(ADMIN2_USERNAME, ADMIN2_EMAIL, ADMIN2_PASSWORD, True, True)
    print(f"{'Created' if created else 'Already exists, skipped'} superuser: {ADMIN2_USERNAME}")
else:
    print(f"DJANGO_ADMIN2_PASSWORD not set -- skipped {ADMIN2_USERNAME}.")

# --- Demo-only regular accounts (not staff/superuser) ---
# These exist purely to populate the UI (e.g. the Admin Accounts panel) --
# you're not expected to log in as them, so a securely random password is
# generated automatically rather than requiring more env vars to manage.
DEMO_USERS = [
    ("miguel123", "miguel@example.com"),
    ("johncena", "john2@email.com"),
]

for username, email in DEMO_USERS:
    if not User.objects.filter(username=username).exists():
        random_password = secrets.token_urlsafe(16)
        create_user_if_missing(username, email, random_password, False, False)
        print(f"Created demo user: {username} (random password, not meant for login)")
    else:
        print(f"Demo user already exists, skipped: {username}")


# ---------------------------------------------------------------------------
# 2. Detection rules
# ---------------------------------------------------------------------------
rules = [
    ("Classic OR Bypass", "signature", r"OR\s+'?1'?\s*=\s*'?1'?", "Boolean-based", 40, True),
    ("UNION SELECT", "signature", r"UNION\s+SELECT", "Union-based", 45, True),
    ("SQL Comment Terminator", "keyword", r"--\s", "Comment-based", 15, True),
    ("Time-Delay Function", "signature", r"SLEEP\(|WAITFOR\s+DELAY", "Time-based", 35, True),
    ("Raw Quote Probe", "anomaly", r"['\"]", "Probing", 10, True),
    ("SQLi - UNION SELECT Attack", "signature", r"(?i)UNION\s+(ALL\s+)?SELECT", "Union-based", 80, True),
    ("SQLi - Always-True Logic (OR 1=1)", "signature", r"(?i)OR\s+['\"]?1['\"]?\s*=\s*['\"]?1|'\s*=\s*'", "Boolean-based", 70, True),
    ("SQLi - Time-Based Blind Delay", "signature", r"(?i)(SLEEP\(\d+\)|WAITFOR\s+DELAY|PG_SLEEP)", "Time-based", 85, True),
    ("XSS - Script Tag Injection", "signature", r"(?i)<script.*?>|javascript:", "Cross-Site Scripting", 75, True),
    ("Path Traversal Sequence", "signature", r"(\.\./|\.\.\\)", "Path Traversal", 60, True),
    ("SQLi Keyword - Comment Truncation", "keyword", r"--|#|/\*", "Comment-based", 30, True),
    ("SQLi Keyword - System Schema Queries", "keyword", r"(?i)(information_schema|sys\.tables|pg_catalog)", "Information Disclosure", 50, True),
    ("Anomaly - Automated Scanner User-Agent", "anomaly", r"(?i)(sqlmap|nikto|nmap|python-requests|gobuster|dirbuster)", "Automated Scanner", 40, True),
    # Not real regex -- need custom rate/ratio-tracking logic, not a per-request pattern match.
    # Kept disabled so they don't silently fail forever.
    ("Anomaly - Request Rate Burst", "anomaly", "RATE_EXCEEDED_60_PER_MIN", "Traffic Spike", 50, False),
    ("Anomaly - Reconnaissance Scanning", "anomaly", "HIGH_404_RATIO", "Reconnaissance", 35, False),
]

created_count = 0
skipped_count = 0

for name, rule_type, pattern, category, risk_weight, is_enabled in rules:
    obj, created = DetectionRule.objects.get_or_create(
        name=name,
        defaults={
            "rule_type": rule_type,
            "pattern": pattern,
            "category": category,
            "risk_weight": risk_weight,
            "is_enabled": is_enabled,
        },
    )
    if created:
        created_count += 1
    else:
        skipped_count += 1

print(f"Detection rules: {created_count} created, {skipped_count} already existed.")