import re
content = 'const apiKey = "***"\nconst stripeKey = "sk_tes...7890"\n'

# Test GENERIC_SECRET_JS
pattern = re.compile(r"(?i)(?<![\'\"]#)(?:const|let|var)\s+(secretKey|jwtSecret|apiKey|password|token)\s*=\s*[\"']([^\"']{3,})[\"'](?![\w\d])")
for m in pattern.finditer(content):
    print('GENERIC_SECRET_JS:', repr(m.group(0)), 'group1:', m.group(1), 'group2:', m.group(2))

# Test Stripe pattern
pattern2 = re.compile(r'sk_test_[0-9a-zA-Z]{16,}')
for m in pattern2.finditer(content):
    print('STRIPE:', m.group(0))