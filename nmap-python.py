import csv
import xml.etree.ElementTree as ET

# Define the name of the Nmap XML output file
filename = "output.xml"

# Define the name of the output CSV file
csvfile = "output.csv"

# Open the CSV file for writing
with open(csvfile, "w", newline="") as f:
    writer = csv.writer(f)

    # Write the CSV header row
    writer.writerow(
        [
            "IP Address",
            "Hostname",
            "Operating System",
            "MAC Address",
            "Protocol",
            "Port",
            "State",
            "Service",
            "Vulnerability",
            "Severity",
        ]
    )

    # Parse the XML file
    tree = ET.parse(filename)
    root = tree.getroot()

    # Loop over the "host" elements in the XML file
    for host in root.findall("host"):
        # Extract the hostname, IP address, and MAC address (if available)
        hostname = host.find("hostnames/hostname").get("name")
        ip = host.find("address").get("addr")
        mac = (
            host.find('address[@addrtype="mac"]').get("addr", "")
            if host.find('address[@addrtype="mac"]') is not None
            else ""
        )

        # Extract the operating system information (if available)
        os = ""
        osmatch = host.find("os/osmatch")
        if osmatch is not None:
            os = osmatch.get("name")

        # Extract the port and service information (if available)
        for port in host.findall("ports/port"):
            portid = port.get("portid")
            protocol = port.get("protocol")
            state = port.find("state").get("state")
            service = (
                port.find("service").get("name", "")
                if port.find("service") is not None
                else ""
            )

            # Extract the vulnerability information (if available)
            for script in port.findall("script"):
                if script.get("id") == "vulners":
                    for vuln in script.findall("table/table"):
                        vulnname = vuln.find('elem[@key="id"]').text
                        severity = vuln.find('elem[@key="cvss"]').text
                        writer.writerow(
                            [
                                ip,
                                hostname,
                                os,
                                mac,
                                protocol,
                                portid,
                                state,
                                service,
                                vulnname,
                                severity,
                            ]
                        )

