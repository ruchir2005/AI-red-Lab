"""Default guardrail rules (taken from the original app/main.py), hardening rules and block messages."""

DEFAULT_RULES = {
    "injection": [
        r"ignore .*previous .*instructions",
        r"ignore .*following .*instructions",
        r"stop everything",
        r"just print",
        r"just say",
        # Jailbreak / role-play
        r"\bdan\b",
        r"unrestricted .*role",
        r"fictional .*role",
        r"respond with exactly",
        # Scope / mode bypass
        r"leave .*customer[- ]support mode",
        r"leave .*support mode",
        r"switch .*customer[- ]support mode",
        r"output only .*marker",
    ],
    "sensitive": [
        r"system prompt",
        r"hidden instructions",
        r"internal test secret",
        r"northwind_test_key",
        r"repeat exactly .*instructions",
        # Indirect system-prompt extraction
        r"reveal .*instructions .*define .*role",
        r"instructions .*define .*role",
        r"reveal .*role .*instructions",
    ],
    "obfuscation": [
        r"(?:\b[a-zA-Z]\s+){5,}[a-zA-Z]\b",
        r"(?:\b[a-zA-Z]\s+){3,}[a-zA-Z]\s*/",
    ],
    "scope_allow": [
        r"\bmy order\b", r"\border status\b", r"\border number\b", r"\btrack(ing)? (my )?(order|package)\b",
        r"\breturn (my |an |a |this )?(item|product|order|purchase|package)\b", r"\breturn policy\b",
        r"\brefund\b", r"\brefund status\b", r"\bshipping\b", r"\bdelivery\b", r"\bproduct\b", r"\bproducts\b",
    ],
    "output_leak": [
        r"NORTHWIND_TEST_KEY\s*=",
        r"NW_TEST_78291",
        r"You are the customer-support assistant for Northwind Retail",
    ],
}

# Rules added by "Apply recommended hardening" (each closes a gap found by the built-in suite).
HARDENING_RULES = {
    "injection": [
        r"disregard .*(prior|previous|above) .*(rules|instructions)",
        r"ignorez .*instructions",
        r"(decode|base64)\b.{0,40}\b(follow|do what|execute|obey|run)",
        r"\bd\W*a\W*n\b",
    ],
    "sensitive": [
        r"(spell|one character per line|letter by letter).*(key|secret)",
        r"repeat everything above",
        r"initial (setup )?rules",
    ],
    "policy": [
        r"ransomware|keylogger|malware|phishing",
        r"other customers|email addresses|home address|customer who ordered",
        r"without (any )?verification",
        r"cancel all",
        r"discount (code|coupon)",
        r"\blifetime\b",
        r"certified safe",
    ],
    "output_leak": [
        r"N\W*W\W*_?\W*T\W*E\W*S\W*T\W*_?\W*7\W*8\W*2\W*9\W*1",
    ],
    "output_unsafe": [
        r"<script",
        r"!\[[^\]]*\]\(https?://",
    ],
}
HARDEN_SETTINGS = {"normalize": "1", "max_output_chars": "1500"}

DEFAULT_SETTINGS = {"normalize": "0", "max_input_chars": "2000", "max_output_chars": "0"}

BLOCK_MESSAGES = {
    "injection": "Request blocked: suspected prompt injection.",
    "sensitive": "Request blocked: access to internal instructions or confidential information is not allowed.",
    "policy": "Request blocked: this request is not permitted by store policy.",
    "obfuscation": "Request blocked: suspected obfuscated instruction.",
    "scope": "I can only help with Northwind Retail orders, returns, refunds, products, shipping, delivery, or tracking.",
    "length_in": "Request blocked: input exceeds the allowed length.",
    "output_leak": "Response blocked: potential confidential information leakage detected.",
    "output_unsafe": "Response blocked: unsafe content detected.",
    "length_out": "Response blocked: response exceeds the allowed length.",
}
