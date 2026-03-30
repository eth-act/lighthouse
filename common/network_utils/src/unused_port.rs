use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::LazyLock;

/// Base port for the partitioned test port range (10000–29999).
const PARTITION_BASE: u16 = 10000;
/// Number of ports per process partition.
const PARTITION_SIZE: u16 = 200;
/// Total partitions; keeps the range within 10000–29999.
const NUM_PARTITIONS: u32 = 100;

/// Maps partition base → next port to try within that partition.
static PORT_CURSORS: LazyLock<Mutex<HashMap<u16, u16>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Copy, Clone)]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Copy, Clone)]
pub enum IpVersion {
    Ipv4,
    Ipv6,
}

/// Returns the start of this process's port partition, derived from the PID.
///
/// Each OS process gets a distinct 200-port band, so concurrent test processes
/// (which nextest launches as separate PIDs) land in different bands and cannot
/// collide on the same port.
fn partition_base() -> u16 {
    PARTITION_BASE + ((std::process::id() % NUM_PARTITIONS) as u16) * PARTITION_SIZE
}

/// A convenience wrapper over [`zero_port`].
pub fn unused_tcp4_port() -> Result<u16, String> {
    zero_port(Transport::Tcp, IpVersion::Ipv4)
}

/// A convenience wrapper over [`zero_port`].
pub fn unused_udp4_port() -> Result<u16, String> {
    zero_port(Transport::Udp, IpVersion::Ipv4)
}

/// A convenience wrapper over [`zero_port`].
pub fn unused_tcp6_port() -> Result<u16, String> {
    zero_port(Transport::Tcp, IpVersion::Ipv6)
}

/// A convenience wrapper over [`zero_port`].
pub fn unused_udp6_port() -> Result<u16, String> {
    zero_port(Transport::Udp, IpVersion::Ipv6)
}

/// Finds an available port using a per-process port partition.
///
/// Each process is assigned a 200-port band derived from its PID, keeping
/// concurrent test processes out of each other's port ranges.  A per-partition
/// cursor tracks the next port to try, so allocations advance sequentially
/// without rescanning already-used ports.
///
/// The lock is held for the duration of the scan to prevent two concurrent
/// callers within the same process from receiving the same port.
///
/// Returns an error if the partition is exhausted.
pub fn zero_port(transport: Transport, ipv: IpVersion) -> Result<u16, String> {
    let localhost: IpAddr = match ipv {
        IpVersion::Ipv4 => Ipv4Addr::LOCALHOST.into(),
        IpVersion::Ipv6 => Ipv6Addr::LOCALHOST.into(),
    };

    let base = partition_base();
    let end = base + PARTITION_SIZE;
    let mut cursors = PORT_CURSORS.lock();
    let start = *cursors.entry(base).or_insert(base);

    for port in start..end {
        let addr = SocketAddr::new(localhost, port);
        let bindable = match transport {
            Transport::Tcp => TcpListener::bind(addr).is_ok(),
            Transport::Udp => UdpSocket::bind(addr).is_ok(),
        };
        if bindable {
            cursors.insert(base, port + 1);
            return Ok(port);
        }
    }

    Err(format!(
        "Could not find an unused port in {start}..{end} (pid-based partition).",
    ))
}
