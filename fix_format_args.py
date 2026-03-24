import os
import re

for root, _, files in os.walk('tests'):
    for file in files:
        if not file.endswith('.rs'): continue
        path = os.path.join(root, file)
        with open(path, 'r') as f:
            content = f.read()
        orig = content

        content = content.replace('format!("{}/network/config")', 'format!("{}/network/config", gateway_url)')
        content = content.replace('format!("{}/simulator/set-state")', 'format!("{}/simulator/set-state", gateway_url)')
        content = content.replace('format!("{}/simulator/generate-blocks/{}")', 'format!("{}/simulator/generate-blocks/{}", gateway_url, num_blocks)')
        content = content.replace('format!("{}/vm-values/query")', 'format!("{}/vm-values/query", gateway_url)')
        
        content = content.replace('Interactor::new(GATEWAY_URL)', 'Interactor::new(&gateway_url)')
        content = content.replace('use test_utils::GATEWAY_URL;', '')

        if orig != content:
            with open(path, 'w') as f:
                f.write(content)
