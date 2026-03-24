import os
import glob
import re

test_dir = '/Users/robertsasu/RustProjects/agentic-payments/mx-agentic-commerce-tests/tests'

files_to_fix = []
for root, _, files in os.walk(test_dir):
    for f in files:
        if f.endswith('.rs'):
            files_to_fix.append(os.path.join(root, f))

for fpath in files_to_fix:
    with open(fpath, 'r') as f:
        content = f.read()

    # 1. Add gateway_url definition
    if "let port = pm.start_chain_simulator()" in content and "let gateway_url =" not in content:
        content = re.sub(
            r'let port = pm\.start_chain_simulator\(\)\n\s*\.expect\("Failed to start simulator"\);\n\s*sleep\(Duration::from_secs\(2\)\)\.await;',
            r'let port = pm.start_chain_simulator()\n        .expect("Failed to start simulator");\n    let gateway_url = format!("http://localhost:{}", port);\n    sleep(Duration::from_secs(2)).await;',
            content
        )
        
    # 2. Fix generate_blocks_on_simulator args
    content = re.sub(r'generate_blocks_on_simulator\(([0-9]+)\)\.await;', r'generate_blocks_on_simulator(\1, &gateway_url).await;', content)
    
    # 3. Fix process manager tests that only sleep but don't define gateway_url
    if "const GATEWAY_URL: &str =" in content:
        content = re.sub(r'const GATEWAY_URL: &str = "[^"]+";\n?', '', content)
        content = content.replace("GATEWAY_URL", "&gateway_url")
        content = content.replace("crate::common::&gateway_url", "crate::common::GATEWAY_URL") # undo if it replaced imports
        
    # 4. Remove 'GATEWAY_URL' import from common
    content = re.sub(r'use crate::common::GATEWAY_URL;\n?', '', content)

    # 5. Fix suite_u2_facilitator_advanced alice_addr -> alice_address
    if "suite_u2_facilitator_advanced.rs" in fpath:
        content = content.replace("alice_address,", "alice_addr,")
        content = content.replace("&alice_address", "&alice_addr")
        
    # 6. Fix test_payment_errors fund_address_on_simulator_custom
    if "test_payment_errors.rs" in fpath:
        content = content.replace("fund_address_on_simulator_custom,", "")
        
    with open(fpath, 'w') as f:
        f.write(content)

print("Done python fix script")
