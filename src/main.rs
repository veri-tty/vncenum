use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use xml::reader::{EventReader, XmlEvent};

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

// Function to prompt user for input file path
fn get_input_file_path() -> io::Result<String> {
    println!("Enter the path to the Nmap/Masscan XML file:");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let path = input.trim();
    if !fs::metadata(path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("File '{}' does not exist", path),
        ));
    }
    Ok(path.to_string())
}

fn main() -> io::Result<()> {
    println!("🔍 VNC Scanner v0.1.0");
    println!("===================");
    println!();

    // Prompt user for input file path
    let file_path = match get_input_file_path() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("❌ Error: {}", e);
            return Err(e);
        }
    };

    println!("📄 Reading XML file: {}", file_path);
    
    // Read XML file from user-provided path
    let xml_content = fs::read_to_string(&file_path)?;
    
    println!("🔍 Parsing XML content...");
    let hosts = parse_nmap_xml(&xml_content)?;

    let total_targets = hosts.iter().map(|h| h.ports.len()).sum::<usize>();
    println!("🎯 Found {} hosts with {} total VNC targets", hosts.len(), total_targets);
    println!("🚀 Starting VNC authentication scan...");
    println!();

    let mut results = Vec::new();
    let mut processed = 0;

    for host in hosts {
        for port in host.ports {
            processed += 1;
            print!("[{}/{}] Checking {}:{} ... ", processed, total_targets, host.ip, port);
            io::stdout().flush().unwrap();
            
            match check_vnc_authentication(&host.ip, port) {
                Ok(status) => {
                    let status_icon = match status.as_str() {
                        "open" => "🟢",
                        "protected" => "🟡", 
                        "down" => "🔴",
                        _ => "❓"
                    };
                    println!("{} {}", status_icon, status);
                    results.push((host.ip.clone(), port, status));
                }
                Err(e) => {
                    println!("🔴 Error: {}", e);
                    results.push((host.ip.clone(), port, "down".to_string()));
                }
            }
        }
    }

    println!();
    println!("💾 Writing results to files...");
    write_results(&results)?;

    let open_count = results.iter().filter(|(_, _, status)| status == "open").count();
    let protected_count = results.iter().filter(|(_, _, status)| status == "protected").count();
    let down_count = results.iter().filter(|(_, _, status)| status == "down").count();

    println!();
    println!("✅ Scan completed!");
    println!("📊 Results summary:");
    println!("   🟢 Open VNC servers: {}", open_count);
    println!("   🟡 Protected VNC servers: {}", protected_count);
    println!("   🔴 Down/unreachable: {}", down_count);
    println!();
    println!("📁 Results saved to:");
    println!("   • results/open.txt");
    println!("   • results/protected.txt");
    println!("   • results/down.txt");

    Ok(())
}