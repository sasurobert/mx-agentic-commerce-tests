import os

for root, _, files in os.walk('tests'):
    for file in files:
        if not file.endswith('.rs'): continue
        path = os.path.join(root, file)
        with open(path, 'r') as f:
            content = f.read()

        orig = content
        
        content = content.replace("let _ = let port = pm.start_chain_simulator();", "let port = pm.start_chain_simulator().unwrap();")
        content = content.replace("let port = pm.start_chain_simulator().expect", "let port = pm.start_chain_simulator().unwrap(); // .expect")
        
        # fix expect if it was like:
        # let port = pm.start_chain_simulator()
        #     .expect("...");
        # The python script might have just done:
        # let port = pm.start_chain_simulator()
        #     .expect("Failed to start simulator");
        # wait, start_chain_simulator now returns Result<u16, Error>. So expect works fine!

        # wait, if original was:
        # pm.start_chain_simulator(808X).expect("...");
        # replaced:
        # let port = pm.start_chain_simulator().expect("...");
        # This is perfectly valid Rust.
        
        if orig != content:
            with open(path, 'w') as f:
                f.write(content)
