use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use std::path::PathBuf;

pub struct ProcessManager {
    children: Vec<Child>,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            children: Vec::new(),
        }
    }

    pub fn start_chain_simulator(&mut self, port: u16) -> Result<(), std::io::Error> {
        println!("Starting Chain Simulator on port {}...", port);
        
        let mut cmd_name = "mx-chain-simulator-go".to_string();
        
        // Check common locations if not in PATH
        if Command::new(&cmd_name).stdout(Stdio::null()).stderr(Stdio::null()).spawn().is_err() {
             // Check common locations if not in PATH
             if let Ok(cwd) = std::env::current_dir() {
                 let local_bin = cwd.join("mx-chain-simulator-go");
                 if local_bin.exists() {
                     cmd_name = local_bin.to_string_lossy().to_string();
                 } else {
                     if let Ok(home) = std::env::var("HOME") {
                        let go_bin = PathBuf::from(home).join("go/bin/mx-chain-simulator-go");
                        if go_bin.exists() {
                            cmd_name = go_bin.to_string_lossy().to_string();
                        }
                     }
                 }
             }
        }

        // Check if port is already listening (idempotent start)
        if TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
            println!("Chain Simulator already running on port {}.", port);
            return Ok(());
        }

        let child = Command::new(&cmd_name)
            .arg("--server-port")
            .arg(port.to_string())
            .arg("--rounds-per-epoch")
            .arg("20")
            .arg("--skip-configs-download")
            .stdout(Stdio::inherit()) 
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                println!("Failed to start chain simulator. Ensure 'mx-chain-simulator-go' is in PATH or ~/go/bin.");
                e
            })?;

        self.children.push(child);
        self.wait_for_port(port, 120);
        println!("Chain Simulator started.");
        Ok(())
    }

    pub fn start_node_service(
        &mut self,
        name: &str,
        cwd: &str,
        script: &str,
        env: Vec<(&str, &str)>,
        port: u16,
    ) -> Result<(), std::io::Error> {
        println!("Starting {} on port {}...", name, port);
        let mut cmd = Command::new("node");
        cmd.current_dir(cwd)
            .arg(script)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        for (key, val) in env {
            cmd.env(key, val);
        }

        let child = cmd.spawn()?;
        self.children.push(child);
        self.wait_for_port(port, 20);
        println!("{} started.", name);
        Ok(())
    }

    fn wait_for_port(&self, port: u16, retries: u32) {
        for _ in 0..retries {
            if TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        panic!(
            "Failed to connect to port {} after {} retries",
            port, retries
        );
    }
}

impl Drop for ProcessManager {
    fn drop(&mut self) {
        for mut child in self.children.drain(..) {
            let _ = child.kill();
            let _ = child.wait();
        }

        // Kill any orphaned chain-simulator processes
        let _ = Command::new("pkill")
            .arg("-f")
            .arg("mx-chain-simulator-go")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        // Wait for port 8085 to be fully released (TIME_WAIT cleanup)
        let port = 8085u16;
        for i in 0..30 {
            if TcpStream::connect(format!("127.0.0.1:{}", port)).is_err() {
                if i > 0 {
                    println!("Port {} released after {}ms.", port, i * 500);
                }
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        println!("Warning: port {} still in use after 15s cleanup wait.", port);
    }
}
