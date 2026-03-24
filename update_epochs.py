import re

with open('config/node/config/enableEpochs.toml', 'r') as f:
    content = f.read()

# Replace any number that is <= 999 with 0 for EnableEpochs configurations
# E.g., ESDTEnableEpoch = 1 -> ESDTEnableEpoch = 0

def repl(match):
    val = int(match.group(2))
    if val < 999999: # keep 9999999 as is
        return match.group(1) + "0"
    return match.group(0)

new_content = re.sub(r'([A-Za-z]+EnableEpoch\s*=\s*)(\d+)', repl, content)
new_content = re.sub(r'(EpochEnable\s*=\s*)(\d+)', repl, new_content)
new_content = re.sub(r'(EnableEpoch\s*=\s*)(\d+)', repl, new_content)

with open('config/node/config/enableEpochs.toml', 'w') as f:
    f.write(new_content)

print("Updated enableEpochs.toml")
