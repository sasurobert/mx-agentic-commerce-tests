import os
import re

dir_path = "tests/pkg_1_identity"
for filename in os.listdir(dir_path):
    if filename.endswith(".rs"):
        filepath = os.path.join(dir_path, filename)
        with open(filepath, 'r') as f:
            content = f.read()
            
        # 1. Add `let gateway_url = format!("http://localhost:{}", port);` after `sleep(Duration::from_secs(2)).await;` if it's not there.
        # We need to be careful not to duplicate it.
        pattern = r'(sleep\(Duration::from_secs\(2\)\)\.await;\n)(\s*)(let mut interactor)'
        replacement = r'\1\2let gateway_url = format!("http://localhost:{}", port);\n\n\2\3'
        content = re.sub(pattern, replacement, content)
        
        # 2. Fix issue_fungible_esdt_custom missing argument in common/mod.rs: 
        # Wait, the error for issue_fungible_esdt_custom was in tests/common/mod.rs? 
        # Let's fix that separately.
        
        # 3. test_service_configs.rs has: const GATEWAY_URL: &str = "http://localhost:8088";
        # Let's remove this const so it doesn't conflict or confuse things.
        content = re.sub(r'const GATEWAY_URL: &str = "http://localhost:\d+";[^\n]*\n', '', content)
        
        with open(filepath, 'w') as f:
            f.write(content)

# Fix tests/common/mod.rs
common_path = "tests/common/mod.rs"
with open(common_path, 'r') as f:
    common_content = f.read()

# Fix issue_fungible_esdt_custom call inside common/mod.rs
common_content = re.sub(
    r'issue_fungible_esdt_custom\(\n\s*interactor,\n\s*issuer,\n\s*name,\n\s*ticker,\n\s*initial_supply,\n\s*decimals,\n\s*\)',
    r'issue_fungible_esdt_custom(\n        interactor,\n        issuer,\n        name,\n        ticker,\n        initial_supply,\n        decimals,\n        gateway_url,\n    )',
    common_content
)

with open(common_path, 'w') as f:
    f.write(common_content)
