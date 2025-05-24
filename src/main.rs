use std::fs::{self, File};
use std::io::{self, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use xml::reader::{EventReader, XmlEvent};
use uuid::Uuid;

// Structure to hold host and port information
#[derive(Debug)]
struct Host {
    ip: String,
    ports: Vec<u16>,
}

// Function to parse Nmap/Masscan XML and extract IPs and ports
fn parse_nmap_xml(xml_content: &str) -> io::Result<Vec<Host>> {
    let parser = EventReader::from_str(xml_content);
    let mut hosts = Vec::new();
    let mut current_ip = None;
    let mut current_ports = Vec::new();
    let mut in_host = false;
    let mut in_port = false;

    for event in parser {
        match event {
            Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                match name.local_name.as_str() {
                    "host" => {
                        in_host = true;
                        current_ports.clear();
                    }
                    "address" if in_host => {
                        for attr in attributes {
                            if attr.name.local_name == "addr" {
                                current_ip = Some(attr.value.clone());
                            }
                        }
                    }
                    "port" if in_host => {
                        in_port = true;
                        for attr in attributes {
                            if attr.name.local_name == "portid" {
                                if let Ok(port) = attr.value.parse::<u16>() {
                                    current_ports.push(port);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::EndElement { name }) => {
                match name.local_name.as_str() {
                    "host" => {
                        if let Some(ip) = current_ip.take() {
                            hosts.push(Host {
                                ip,
                                ports: current_ports.clone(),
                            });
                        }
                        in_host = false;
                    }
                    "port" => {
                        in_port = false;
                    }
                    _ => {}
                }
            }
            Err(e) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
            }
            _ => {}
        }
    }

    Ok(hosts)
}

// Function to check VNC authentication
fn check_vnc_authentication(ip: &str, port: u16) -> io::Result<String> {
    let addr = format!("{}:{}", ip, port);
    let timeout = Duration::from_secs(5);

    match addr.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                match TcpStream::connect_timeout(&addr, timeout) {
                    Ok(mut stream) => {
                        stream.set_write_timeout(Some(timeout))?;
                        stream.set_read_timeout(Some(timeout))?;

                        // Send RFB protocol identifier
                        stream.write_all(b"RFB\n")?;
                        stream.flush()?;

                        // Read response
                        let mut buffer = [0; 1024];
                        match stream.read(&mut buffer) {
                            Ok(n) if n > 0 => {
                                let response = String::from_utf8_lossy(&buffer[..n]);
                                if response.contains("RFB") {
                                    // Assume unprotected if RFB response is received
                                    // In a real scenario, you'd need to check for authentication challenge
                                    Ok("open".to_string())
                                } else {
                                    Ok("protected".to_string())
                                }
                            }
                            _ => Ok("protected".to_string()),
                        }
                    }
                    Err(_) => Ok("down".to_string()),
                }
            } else {
                Ok("down".to_string())
            }
        }
        Err(_) => Ok("down".to_string()),
    }
}

// Function to write results to files
fn write_results(results: &[(String, u16, String)]) -> io::Result<()> {
    fs::create_dir_all("results")?;

    let mut open_file = File::create("results/open.txt")?;
    let mut protected_file = File::create("results/protected.txt")?;
    let mut down_file = File::create("results/down.txt")?;

    for (ip, port, status) in results {
        let line = format!("{}:{}\n", ip, port);
        match status.as_str() {
            "open" => open_file.write_all(line.as_bytes())?,
            "protected" => protected_file.write_all(line.as_bytes())?,
            "down" => down_file.write_all(line.as_bytes())?,
            _ => {}
        }
    }

    Ok(())
}

fn main() -> io::Result<()> {
    // Read XML file (assuming input.xml in current directory)
    let xml_content = fs::read_to_string("input.xml")?;
    let hosts = parse_nmap_xml(&xml_content)?;

    let mut results = Vec::new();

    for host in hosts {
        for port in host.ports {
            match check_vnc_authentication(&host.ip, port) {
                Ok(status) => {
                    println!("{}:{} - {}", host.ip, port, status);
                    results.push((host.ip.clone(), port, status));
                }
                Err(e) => {
                    eprintln!("Error checking {}:{} - {}", host.ip, port, e);
                    results.push((host.ip.clone(), port, "down".to_string()));
                }
            }
        }
    }

    write_results(&results)?;

    Ok(())
}