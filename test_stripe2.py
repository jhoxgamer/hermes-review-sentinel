import os
import re

# Test what the Stripe patterns actually match
test_values = [
    "sk_liv...7890",  # test value from test file
    "os.getenv("API_KEY_1", "CHANGE_ME_IN_PRODUCTION")",  # 24 chars after sk_live_
    "os.getenv("API_KEY_2", "CHANGE_ME_IN_PRODUCTION")",  # 20 chars
    "os.getenv("API_KEY_3", "CHANGE_ME_IN_PRODUCTION")",  # 16 chars
    "sk_test_abcdefghi",  # 11 chars
    "sk_test_abcdef",  # 10 chars
]

# Current patterns
for val in test_values:
    pattern = re.compile(r'sk_live_[0-9a-zA-Z\.]{10,}')
    match = pattern.search(val)
    if match:
        print(f"CURRENT sk_live_: MATCHES '{val}' -> {match.group(0)}")
    else:
        print(f"CURRENT sk_live_: NO MATCH for '{val}'")

print("---")
for val in test_values:
    pattern = re.compile(r'sk_test_[0-9a-zA-Z\.]{10,}')
    match = pattern.search(val)
    if match:
        print(f"CURRENT sk_test_: MATCHES '{val}' -> {match.group(0)}")
    else:
        print(f"CURRENT sk_test_: NO MATCH for '{val}'")