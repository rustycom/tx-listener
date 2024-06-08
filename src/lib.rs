use pcap::Packet;
use etherparse::{PacketHeaders, TransportHeader, IpHeader};
use log::{info, warn, LevelFilter};
use solana_sdk::transaction::Transaction;
use std::fs::OpenOptions;
use std::io::Write;
use bincode;
use env_logger::Builder;
use std::error::Error;

/// Initializes the logger with specified settings.
pub fn initialize_logger() {
    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("debug.log")
        .unwrap();

    Builder::new()
        .format(move |buf, record| {
            let mut log_file = log_file.try_clone().unwrap();
            writeln!(log_file, "{} - {}", record.level(), record.args()).unwrap();
            if record.level() > LevelFilter::Info {
                writeln!(buf, "{} - {}", record.level(), record.args()).unwrap();
            }
            Ok(())
        })
        .filter(None, LevelFilter::Trace)
        .init();
}

/// Processes a single network packet.
///
/// # Arguments
///
/// * `packet` - A reference to the packet to process.
pub fn process_packet(packet: &Packet) {
    if let Some(udp_payload) = extract_udp_payload_from_packet(packet) {
        process_udp_payload(udp_payload);
    }
}

/// Extracts the UDP payload from a network packet.
///
/// # Arguments
///
/// * `packet` - A reference to the packet from which to extract the UDP payload.
///
/// # Returns
///
/// An `Option` containing a slice of the UDP payload if it exists, or `None` otherwise.
pub fn extract_udp_payload_from_packet<'a>(packet: &'a Packet) -> Option<&'a [u8]> {
    match PacketHeaders::from_ethernet_slice(packet.data) {
        Err(value) => {
            info!("Ignoring packet due to {:?}", value);
            None
        }
        Ok(headers) => {
            if let Some(TransportHeader::Udp(_udp_header)) = headers.transport {
                if let Some(IpHeader::Version4(ip_header, _)) = headers.ip {
                    return extract_udp_payload(packet.data, &ip_header);
                }
            } else {
                info!("Non-UDP packet received");
            }
            None
        }
    }
}

/// Extracts the UDP payload from the raw data and IP header.
///
/// # Arguments
///
/// * `data` - A slice of the raw packet data.
/// * `ip_header` - A reference to the IPv4 header.
///
/// # Returns
///
/// An `Option` containing a slice of the UDP payload if it exists, or `None` otherwise.
fn extract_udp_payload<'a>(data: &'a [u8], ip_header: &etherparse::Ipv4Header) -> Option<&'a [u8]> {
    let ethernet_header_len = 14; // Ethernet header is 14 bytes
    let ip_header_len = ip_header.header_len() as usize;
    let udp_header_len = 8; // UDP header is 8 bytes

    let udp_payload_offset = ethernet_header_len + ip_header_len + udp_header_len;
    if data.len() > udp_payload_offset {
        Some(&data[udp_payload_offset..])
    } else {
        None
    }
}

/// Processes the UDP payload by attempting to decode it as a Solana transaction.
///
/// # Arguments
///
/// * `udp_payload` - A slice of the UDP payload.
fn process_udp_payload(udp_payload: &[u8]) {
    match decode_transaction(udp_payload) {
        Ok(transaction_details) => {
            if !transaction_details.signatures.is_empty() && !transaction_details.instructions.is_empty() {
                print_transaction(&transaction_details);
            } else {
                info!("Transaction with empty signatures or instructions, skipping.");
            }
        }
        Err(e) => warn!("Given data packet is not a Solana transaction: {:?}", e),
    }
}

/// Decodes a Solana transaction from the given data.
///
/// # Arguments
///
/// * `data` - A slice of the data to decode.
///
/// # Returns
///
/// A `Result` containing the decoded `TransactionDetails` if successful, or an error if not.
fn decode_transaction(data: &[u8]) -> Result<TransactionDetails, Box<dyn Error>> {
    // Attempt to decode the transaction
    let transaction: Transaction = bincode::deserialize(data)?;
    let transaction_details = TransactionDetails {
        signatures: transaction.signatures.iter().map(|sig| bs58::encode(sig).into_string()).collect(),
        instructions: transaction.message.instructions.iter().map(|instr| format!("{:?}", instr)).collect(),
    };
    Ok(transaction_details)
}

/// Holds the details of a Solana transaction.
#[derive(Debug)]
pub struct TransactionDetails {
    pub signatures: Vec<String>,
    pub instructions: Vec<String>,
}

/// Prints the details of a Solana transaction.
///
/// # Arguments
///
/// * `transaction` - A reference to the transaction details to print.
fn print_transaction(transaction: &TransactionDetails) {
    println!("\nTransaction Details:");
    println!("Signatures: {:?}", transaction.signatures);
    println!("Instructions: {:?}", transaction.instructions);
    // For debug log
    info!("Transaction Details: {:?}", transaction);
}
