import os
import re

def rewrite():
    test_dir = 'tests'
    for root, dirs, files in os.walk(test_dir):
        for file in files:
            if not file.endswith('.rs'): continue
            path = os.path.join(root, file)
            with open(path, 'r') as f:
                content = f.read()
                
            original_content = content

            # Fix common import: remove GATEWAY_URL or replace with gateway_url
            content = re.sub(r'GATEWAY_URL,\s*', '', content)
            content = re.sub(r',\s*GATEWAY_URL', '', content)
            content = re.sub(r'GATEWAY_URL', '', content) # Just in case it's alone, but we'll see
            
            # Since 'GATEWAY_URL' might still be alone in `{ GATEWAY_URL }`, fix it
            content = re.sub(r'\{\s*\}', '', content)
            content = re.sub(r'use crate::common::;', '', content)
            
            # Re-read fresh since GATEWAY_URL replacement above was too broad
            content = original_content
            # Safely remove GATEWAY_URL from common:: imports
            content = re.sub(r'GATEWAY_URL,?', '', content)
            # Remove empty brackets or dangling commas if left
            content = re.sub(r'\{\s*,', '{', content)
            content = re.sub(r',\s*\}', '}', content)
            content = re.sub(r'\{\s*\}', '', content)
            
            # Now the main logic
            # Change pm.start_chain_simulator(PORT) to let port = pm.start_chain_simulator();
            # Wait, start_chain_simulator returns Result<(), Error> currently. I'll change it to Result<u16, Error>
            # So: let port = pm.start_chain_simulator().expect("...");
            content = re.sub(r'pm\.start_chain_simulator\(\d+\)', 'let port = pm.start_chain_simulator()', content)
            
            # the gateway_url definition must be introduced before it's used
            # let's find `let mut interactor = Interactor::new(GATEWAY_URL)`
            # and replace it with:
            # let gateway_url = format!("http://localhost:{}", port);
            # let mut interactor = Interactor::new(&gateway_url)
            
            content = content.replace("Interactor::new(GATEWAY_URL)", "Interactor::new(&gateway_url)")
            content = re.sub(r'Interactor::new\("http://localhost:\d+"\)', 'Interactor::new(&gateway_url)', content)
            
            # The sleep is usually right before interactor creation.
            # We can inject `let gateway_url = format!("http://localhost:{}", port);` right after the sleep or right before Interactor::new.
            content = content.replace("let mut interactor = Interactor::new(&gateway_url)", 
                                      'let gateway_url = format!("http://localhost:{}", port);\n    let mut interactor = Interactor::new(&gateway_url)')
            # sometimes it is let interactor = Interactor::new(&gateway_url)
            content = content.replace("let interactor = Interactor::new(&gateway_url)", 
                                      'let gateway_url = format!("http://localhost:{}", port);\n    let interactor = Interactor::new(&gateway_url)')
                                      
            # Handle crate::common::fund_address_on_simulator_custom
            # fund_address_on_simulator_custom(&wallet, "1...", "http://localhost:808X")
            # -> fund_address_on_simulator_custom(&wallet, "1...", &gateway_url)
            content = re.sub(r'fund_address_on_simulator_custom\(([^,]+),([^,]+),\s*"http://localhost:\d+"\s*\)', 
                             r'fund_address_on_simulator(\1,\2, &gateway_url)', content)
                             
            content = content.replace("fund_address_on_simulator_custom", "fund_address_on_simulator")
            
            # Handle fund_address_on_simulator(..., ...) without gateway_url
            # Wait, fund_address_on_simulator needs to be updated to take &gateway_url
            # Let's just blindly add &gateway_url to fund_address_on_simulator if it has 2 args
            content = re.sub(r'fund_address_on_simulator\(([^,]+),\s*([^,]+?)\)', 
                             r'fund_address_on_simulator(\1, \2, &gateway_url)', content)
            
            # Wait, because of multiline it might not catch it.
            # Let's do it with a more robust regex
            
            # what about get_simulator_chain_id() -> get_simulator_chain_id(&gateway_url)
            content = content.replace("get_simulator_chain_id()", "get_simulator_chain_id(&gateway_url)")
            
            # what about generate_blocks_on_simulator(args) -> generate_blocks_on_simulator(args, &gateway_url)
            content = re.sub(r'generate_blocks_on_simulator\(([^,]+)\)', r'generate_blocks_on_simulator(\1, &gateway_url)', content)

            if content != original_content:
                with open(path, 'w') as f:
                    f.write(content)

if __name__ == "__main__":
    rewrite()
