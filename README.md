# Annwn-Guerrilla

**A Decentralized Peer-to-Peer Security Monitor and Firewall Implementation in Rust**

---

## Overview

**Annwn** is a decentralized, peer-to-peer network security monitoring protocol designed to eliminate the vulnerabilities of centralized security systems by distributing detection, communication, and response across a resilient mesh of cooperating nodes.

**Guerrilla** is a Linux implementation of the Annwn protocol, written in Rust, that enables:

* Fault-tolerant peer discovery and authentication
* Secure, cryptographically signed peer communication
* Passive flood and DDoS attack detection and coordinated response
* Modular extensions including dynamic firewall rules, honeypot monitoring, and a real-time dashboard
* Python API (`Pwyll`) for user-defined event handling and extensibility

---

## Features

* **Decentralized Architecture:** No single point of failure; nodes collaboratively monitor and protect the network.
* **Secure Peer Discovery:** Uses UDP multicast and HMAC-SHA256 validation to maintain trusted peer lists.
* **Authenticated Messaging:** TCP-based communication with cryptographic signatures and message deduplication.
* **Flood and DDoS Detection:** Passive packet monitoring with volume and entropy heuristics for anomaly detection.
* **Automated Flood Blocking:** Dynamic firewall rules to block malicious IPs during flood attacks.
* **Dashboard:** Visualize network topology and events through a web interface.
* **Honeypot Service:** Detects and alerts unauthorized filesystem changes.
* **Python API (Pwyll):** Scriptable event hooks for custom responses to security events.

---

## Getting Started

### Requirements

* Linux environment
* Rust toolchain ([rustup](https://rustup.rs/))
* SQLite3
* `libpcap` development headers (for network capture)
* `iptables`

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/gabfca/Annwn-Guerrilla.git
   cd Annwn-Guerrilla
   ```

2. Build the project:

   ```bash
   cargo build --release
   ```

3. Configure Guerrilla using the provided TOML configuration file. 

---

## Usage

* Run Guerrilla node (must be root):

  ```bash
  ./target/release/guerrilla config.toml
  ```

* Access the web dashboard to monitor network status and events.

* Use the Pwyll Python API to connect to Guerrilla's event log and write custom event handlers.

---

## Architecture Details

* **Core Behaviors:**

  * *CB1:* Peer discovery via UDP multicast and cryptographic validation
  * *CB2:* TCP peer-to-peer message propagation with signed JSON payloads
  * *CB3:* Passive flood monitoring through packet capture and anomaly detection

## Testing and Results

* Successfully detects and removes unreachable nodes from the trusted peer list.
* Demonstrated resilience to high-volume distributed denial-of-service (DDoS) attacks by dynamically blocking offending IPs and maintaining network functionality.

---

## Extending Guerrilla

* Write Python scripts using the `Pwyll` API to receive real-time security events and automate responses or notifications.
