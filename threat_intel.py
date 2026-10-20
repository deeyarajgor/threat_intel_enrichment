import ipaddress #python's built in library to validate IP addresses

def load_iocs(filename):
    """Read IP addresses from a text file"""
    with open(filename, "r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()] #reads each line, strips whitespace, and ignores empty lines

def validate_ip(ip):
    """Returns True if each entry is a valid IP"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def main(): #runs the program and displays results
    iocs = load_iocs("sample_iocs.txt")

    for ip in iocs:
        if validate_ip(ip):
            print(f"[VALID]   {ip}")
        else:
            print(f"[INVALID] {ip}")

if __name__ == "__main__":
    main()
