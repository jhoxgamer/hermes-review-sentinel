import os
import re

# Test with updated patterns
test_values = [
    "sk_liv...7890",  # test value from test file
    "os.getenv("API_KEY_1", "CHANGE_ME_IN_PRODUCTION")",  # 24 chars after sk_live_
    "os.getenv("API_KEY_2", "CHANGE_ME_IN_PRODUCTION")",  # 20 chars
    "os.getenv("API_KEY_3", "CHANGE_ME_IN_PRODUCTION")",  # 16 chars
    "sk_test_abcdefghi",  # 11 chars
    "sk_test_abcdef",  # 10 chars
]

# Updated patterns
for val in test_values:
    pattern = re.compile(r'sk_live?_?[0-9a-zA-Z\.]{8,}')
    match = pattern.search(val)
    if match:
        print(f"UPDATED sk_live?: MATCHES '{val}' -> {match.group(0)}")
    else:
        print(f"UPDATED sk_live?: NO MATCH for '{val}'")