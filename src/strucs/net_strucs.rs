use std::net::SocketAddr;
use libproc::net_info::TcpSIState;

#[derive(Debug, Clone)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub enum ConnectionState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Unknown,
}

impl From<TcpSIState> for ConnectionState {
    fn from(state: TcpSIState) -> Self {
        match state {
            TcpSIState::Closed => ConnectionState::Closed,
            TcpSIState::Listen => ConnectionState::Listen,
            TcpSIState::SynSent => ConnectionState::SynSent,
            TcpSIState::SynReceived => ConnectionState::SynReceived,
            TcpSIState::Established => ConnectionState::Established,
            TcpSIState::FinWait1 => ConnectionState::FinWait1,
            TcpSIState::FinWait2 => ConnectionState::FinWait2,
            TcpSIState::CloseWait => ConnectionState::CloseWait,
            TcpSIState::Closing => ConnectionState::Closing,
            TcpSIState::LastAck => ConnectionState::LastAck,
            TcpSIState::TimeWait => ConnectionState::TimeWait,
            _ => ConnectionState::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub pid: i32,
    pub process_name: String,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub protocol: Protocol,
    pub state: ConnectionState,
    pub bytes_in: u64,
    pub bytes_out: u64,
}