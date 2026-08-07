import os
import re

# Test what the Stripe patterns actually match
test_values = [
    "sk_liv...7890",  # test value
    "os.getenv("API_KEY_1", "CHANGE_ME_IN_PRODUCTION")",  # 24 chars after sk_live_
    "os.getenv("API_KEY_2", "CHANGE_ME_IN_PRODUCTION")",  # 20 chars
    "os.getenv("API_KEY_3", "CHANGE_ME_IN_PRODUCTION")",  # 16 chars
    "sk_test_abcdefghi",  # 11 chars
]

for val in test_values:
    for min_len in [24, 16, 12, 8]:
        pattern = re.compile(f'sk_live_[0-9a-zA-Z]{{{min_len},}}')
        match = pattern.search(val)
        if match:
            print(f"sk_live_ min={min_len}: MATCHES '{val}' -> {match.group(0)}")
            break
    else:
        print(f"sk_live_ NO MATCH for '{val}'")

print("---")
for val in test_values:
    for min_len in [24, 16, 12, 8]:
        pattern = re.compile(f'sk_test_[0-9a-zA-Z]{{{min_len},}}')
        match = pattern.search(val)
        if match:
            print(f"sk_test_ min={min_len}: MATCHES '{val}' -> {match.group(0)}")
            break
    else:
        print(f"sk_test_ NO MATCH for '{val}'")