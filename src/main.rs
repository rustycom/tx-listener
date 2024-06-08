use solana_network_listener::*;
use pcap::{Device, Capture};
use clap::{Arg, Command};

/// The entry point of the Solana Network Listener Interface application.
fn main() {
    // Initialize the logger
    initialize_logger();

    // Parse command-line argument
    let matches = Command::new("Solana Network Listener Interface")
        .version("1.0")
        .about("Captures and processes raw Solana transactions from network interface")
        .arg(
            Arg::new("network_interface_name")
                .short('i')
                .long("interface")
                .help("The name of the network interface to capture packets from")
                .required(true)
                .value_name("NETWORK_INTERFACE_NAME"),
        )
        .get_matches();

    let network_interface_name = matches.get_one::<String>("network_interface_name").expect("Device name is required");

    // Process the network interface device input name
    let device = Device::list().unwrap()
        .into_iter()
        .find(|d| d.name == network_interface_name.as_str())
        .expect("Failed to find the specified network interface device");

    // Open the device interface for packet capture
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .open()
        .unwrap();
    cap.filter("udp port 8001", true).expect("Failed to set filter");

    // Capture packets and process them
    while let Ok(packet) = cap.next_packet() {
        process_packet(&packet);
    }
}
