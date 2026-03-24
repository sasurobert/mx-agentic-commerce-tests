import os
import re

dir_path = "tests/pkg_1_identity"
for filename in os.listdir(dir_path):
    if filename.endswith(".rs"):
        filepath = os.path.join(dir_path, filename)
        with open(filepath, 'r') as f:
            content = f.read()
            
        # Fix start_chain_simulator(808X) -> start_chain_simulator()
        content = re.sub(r'start_chain_simulator\(\d+\)', 'start_chain_simulator()', content)
        
        # We also need gateway_url to be defined if it's missing, but it might be missing in test_token_issuance.rs or test_registration.rs
        # Let's check how many fund_address_on_simulator missing args:
        # Actually this regex just replaces the exact instances if it has 2 args
        content = re.sub(r'fund_address_on_simulator\(([^,]+),\s*([^,\)]+)\)', r'fund_address_on_simulator(\1, \2, &gateway_url)', content)
        
        # Multiline args:
        content = re.sub(r'fund_address_on_simulator\(\n\s*([^,]+),\n\s*([^,\)]+),\n\s*\)', r'fund_address_on_simulator(\n\t\t\1,\n\t\t\2,\n\t\t&gateway_url,\n\t)', content)
        
        # Fix identity registry interactor init
        content = content.replace('IdentityRegistryInteractor::init(&mut interactor, alice_address.clone()).await', 'IdentityRegistryInteractor::init(&mut interactor, alice_address.clone()).await')
        
        with open(filepath, 'w') as f:
            f.write(content)

