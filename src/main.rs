mod strucs {
    pub mod net_strucs;
}

use crate::strucs::net_strucs::{Connection, ConnectionState, Protocol};
use anyhow::Result;
use libproc::proc_pid::{self, ProcType};
use libproc::processes::pids_by_type;

pub fn collect_connections() -> Result<Vec<Connection>> {
    let mut connections: Vec<Connection> = Vec::new();

    if let Ok(pids) = pids_by_type(ProcType::ProcAllPIDS.into()) {
        for pid in pids {
            let pid_i32: i32 = pid as i32;

            // Get process name first
            let process_name = proc_pid::name(pid_i32).unwrap_or_else(|_| "unknown".to_string());

            if process_name != "unknown" {
                connections.push(Connection {
                    pid: pid_i32,
                    process_name,
                    local_addr: "127.0.0.1:0"
                        .parse()
                        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                    remote_addr: "0.0.0.0:0"
                        .parse()
                        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                    protocol: Protocol::Tcp,
                    state: ConnectionState::Unknown,
                    bytes_in: 0,
                    bytes_out: 0,
                });
            }
        }
    }
    Ok(connections)
}

fn main() -> Result<()> {
    println!("Network Monitor - Collecting connections...");

    match collect_connections() {
        Ok(connections) => {
            println!("Found {} processes:", connections.len());
            for conn in connections {
                println!(
                    "PID: {} | Process: {} | Protocol: {:?} | State: {:?}",
                    conn.pid, conn.process_name, conn.protocol, conn.state
                );
            }
        }
        Err(e) => {
            eprintln!("Error collecting connections: {}", e);
        }
    }

    Ok(())
}
