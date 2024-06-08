#[cfg(test)]
mod tests {
    use solana_network_listener::*;
    use pcap::Capture;
    use solana_sdk::transaction::Transaction;
    use solana_sdk::message::Message;
    use solana_sdk::instruction::{Instruction, AccountMeta};
    use solana_sdk::pubkey::Pubkey;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Once;

    static INIT: Once = Once::new();
    static PROCESSED_COUNT: AtomicUsize = AtomicUsize::new(0);

    fn initialize() {
        INIT.call_once(|| {
            // Initialize the logger
            initialize_logger();
        });
    }

    #[test]
    fn test_process_pcap_file() {
        initialize();
        println!("Starting test_process_pcap_file");

        // Path to the sample PCAP file
        let pcap_path = Path::new("tests/data/sample.pcap");

        // Open the PCAP file
        let mut cap = Capture::from_file(pcap_path).expect("Failed to open PCAP file");

        // Read packets from the file and process them
        while let Ok(packet) = cap.next_packet() {
            process_packet(&packet);
            PROCESSED_COUNT.fetch_add(1, Ordering::SeqCst);
        }

        let processed_count = PROCESSED_COUNT.load(Ordering::SeqCst);
        println!("Total UDP packets processed: {}", processed_count);
        assert!(processed_count > 0, "No UDP packets were processed");
    }

    #[test]
    fn test_process_custom_udp_transaction() {
        initialize();
        println!("Starting test_process_custom_udp_transaction");

        // Create a custom Solana transaction
        let instruction = Instruction::new_with_bincode(
            Pubkey::new_unique(),
            &(), // specify the custom type here
            vec![AccountMeta::new(Pubkey::new_unique(), false)],
        );
        let message = Message::new(&[instruction], Some(&Pubkey::new_unique()));
        let transaction = Transaction::new_unsigned(message);

        // Serialize the transaction
        let serialized_transaction = bincode::serialize(&transaction).expect("Failed to serialize transaction");

        // Create mock Ethernet, IP, and UDP headers
        let ethernet_header = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Destination MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source MAC
            0x08, 0x00  // Ethertype: IPv4
        ];

        let ip_header = [
            0x45, // Version and header length
            0x00, // Type of service
            0x00, 0x3c, // Total length
            0x1c, 0x46, // Identification
            0x40, 0x00, // Flags and fragment offset
            0x40, // TTL
            0x11, // Protocol: UDP
            0x00, 0x00, // Header checksum (filled in later)
            0xc0, 0xa8, 0x00, 0x01, // Source IP
            0xc0, 0xa8, 0x00, 0x02  // Destination IP
        ];

        let udp_header = [
            0x1f, 0x40, // Source port (8000)
            0x1f, 0x41, // Destination port (8001)
            0x00, 0x28, // Length
            0x00, 0x00  // Checksum (filled in later)
        ];

        // Combine headers and serialized transaction into one packet
        let mut packet = Vec::new();
        packet.extend_from_slice(&ethernet_header);
        packet.extend_from_slice(&ip_header);
        packet.extend_from_slice(&udp_header);
        packet.extend_from_slice(&serialized_transaction);

        // Create a mock packet
        let pcap_packet = pcap::Packet {
            header: &pcap::PacketHeader {
                ts: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                },
                caplen: packet.len() as u32,
                len: packet.len() as u32,
            },
            data: &packet,
        };

        // Process the mock packet
        process_packet(&pcap_packet);

        // Extract the UDP payload
        let udp_payload = extract_udp_payload_from_packet(&pcap_packet).expect("Failed to extract UDP payload");

        // Deserialize the transaction from the UDP payload
        let deserialized_transaction: Transaction = bincode::deserialize(udp_payload).expect("Failed to deserialize transaction");

        // Assert that the deserialized transaction matches the original transaction
        assert_eq!(transaction.signatures, deserialized_transaction.signatures);
        assert_eq!(transaction.message, deserialized_transaction.message);

        println!("Completed test_process_custom_udp_transaction");
    }
}
