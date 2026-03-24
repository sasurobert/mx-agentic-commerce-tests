import os
import re

for root, _, files in os.walk('tests'):
    for file in files:
        if not file.endswith('.rs'): continue
        path = os.path.join(root, file)
        with open(path, 'r') as f:
            content = f.read()
        orig = content

        # 1. Remove GATEWAY_URL from imports
        content = re.sub(r',\s*GATEWAY_URL', '', content)
        content = re.sub(r'GATEWAY_URL,\s*', '', content)
        content = re.sub(r'GATEWAY_URL\s*\}', '}', content)
        content = re.sub(r'\{\s*GATEWAY_URL\s*\}', '', content)
        content = re.sub(r'use crate::common::;\n', '', content)

        # 2. Fix `let _ = let port = ...`
        content = content.replace("let _ = let port = pm.start_chain_simulator()", "let port = pm.start_chain_simulator().unwrap()")
        content = content.replace("let _ = let port = pm.start_chain_simulator().expect", "let port = pm.start_chain_simulator().expect")

        # 3. Add `let port = pm.start_chain_simulator().unwrap();` if we missed it and it's still `pm.start_chain_simulator(808X)`
        # Wait, if they have `let _ = pm.start_chain_simulator(8085);`, it became `let _ = let port = pm.start_chain_simulator();`
        # What if it's `pm.start_chain_simulator(8085).expect("...");` and was replaced by `let port = pm.start_chain_simulator().expect("...");`? That's correct.
        
        # 4. Sometimes it was `pm.start_chain_simulator(8085)` on a line by itself.
        content = re.sub(r'^\s*pm\.start_chain_simulator\(\d+\);', '    let port = pm.start_chain_simulator().unwrap();', content, flags=re.MULTILINE)
        content = re.sub(r'^\s*pm\.start_chain_simulator\(\d+\)', '    let port = pm.start_chain_simulator().unwrap()', content, flags=re.MULTILINE)

        if orig != content:
            with open(path, 'w') as f:
                f.write(content)

