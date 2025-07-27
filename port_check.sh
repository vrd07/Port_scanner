#!/bin/bash

# Enhanced Port Scanner for Pentesting
# Author: Security Tester
# Usage: For authorized penetration testing only

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Default values
TARGET=""
TIMEOUT=3
VERBOSE=false
OUTPUT_FILE=""
SCAN_TYPE="quick"
THREADS=10

# Common pentesting port lists
QUICK_PORTS=(21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1723 3306 3389 5432 5900 6379 8080 8443)
FULL_PORTS=($(seq 1 65535))
WEB_PORTS=(80 443 8080 8443 8000 8008 8888 9000 9090 3000 5000 7000 7001 8001 8009 8181 8834 9001 9999 10000)
DATABASE_PORTS=(1433 1521 3306 5432 27017 6379 11211 9200 9300)

usage() {
    echo "Enhanced Port Scanner for Penetration Testing"
    echo "Usage: $0 -t target [options]"
    echo ""
    echo "Required:"
    echo "  -t target    Target IP/hostname"
    echo ""
    echo "Options:"
    echo "  -s type      Scan type: quick, full, web, database (default: quick)"
    echo "  -T timeout   Connection timeout in seconds (default: 3)"
    echo "  -o file      Output results to file"
    echo "  -v           Verbose output"
    echo "  -j threads   Number of parallel threads (default: 10)"
    echo "  -h           Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.100 -s quick -v"
    echo "  $0 -t target.com -s web -o results.txt"
    echo "  $0 -t 10.10.10.10 -s full -j 20"
    exit 1
}

# Parse arguments
while getopts "t:s:T:o:vj:h" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        s) SCAN_TYPE="$OPTARG" ;;
        T) TIMEOUT="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        v) VERBOSE=true ;;
        j) THREADS="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validate required arguments
if [[ -z "$TARGET" ]]; then
    echo -e "${RED}Error: Target is required${NC}"
    usage
fi

# Logging function
log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "$message"
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo -e "$message" | sed 's/\x1b\[[0-9;]*m//g' >> "$OUTPUT_FILE"
    fi
}

# Banner grabbing function
grab_banner() {
    local port=$1
    local banner=""
    
    case $port in
        21|22|23|25|110|143|993|995)
            banner=$(timeout 2 nc "$TARGET" "$port" 2>/dev/null | head -1 | tr -d '\r\n')
            ;;
        80|8080|8000|8008|8888|9000|3000|5000|7000|8001|8009|8181|9001|9999|10000)
            banner=$(curl -I -s -m 2 --connect-timeout 2 "http://$TARGET:$port" 2>/dev/null | grep -i "server:" | head -1 | tr -d '\r\n')
            ;;
        443|8443|8834)
            banner=$(curl -k -I -s -m 2 --connect-timeout 2 "https://$TARGET:$port" 2>/dev/null | grep -i "server:" | head -1 | tr -d '\r\n')
            ;;
    esac
    
    echo "$banner"
}

# Enhanced port checking with service detection
check_port() {
    local port=$1
    local service_name=""
    local status="CLOSED"
    local banner=""
    
    # Service identification
    case $port in
        21) service_name="FTP" ;;
        22) service_name="SSH" ;;
        23) service_name="Telnet" ;;
        25) service_name="SMTP" ;;
        53) service_name="DNS" ;;
        80) service_name="HTTP" ;;
        110) service_name="POP3" ;;
        111) service_name="RPC" ;;
        135) service_name="RPC" ;;
        139) service_name="NetBIOS" ;;
        143) service_name="IMAP" ;;
        443) service_name="HTTPS" ;;
        445) service_name="SMB" ;;
        993) service_name="IMAPS" ;;
        995) service_name="POP3S" ;;
        1433) service_name="MSSQL" ;;
        1521) service_name="Oracle" ;;
        1723) service_name="PPTP" ;;
        3306) service_name="MySQL" ;;
        3389) service_name="RDP" ;;
        5432) service_name="PostgreSQL" ;;
        5900) service_name="VNC" ;;
        6379) service_name="Redis" ;;
        8080) service_name="HTTP-Alt" ;;
        8443) service_name="HTTPS-Alt" ;;
        9200) service_name="Elasticsearch" ;;
        27017) service_name="MongoDB" ;;
        *) service_name="Unknown" ;;
    esac
    
    # Port connectivity check
    if command -v nc >/dev/null 2>&1; then
        if nc -z -w$TIMEOUT "$TARGET" "$port" 2>/dev/null; then
            status="OPEN"
        fi
    else
        if timeout $TIMEOUT bash -c "echo >/dev/tcp/$TARGET/$port" 2>/dev/null; then
            status="OPEN"
        fi
    fi
    
    # If port is open, try banner grabbing
    if [[ "$status" == "OPEN" ]]; then
        banner=$(grab_banner $port)
        
        if [[ "$VERBOSE" == true ]]; then
            log "${GREEN}[+] $port/$service_name: OPEN${NC}"
            [[ -n "$banner" ]] && log "    ${BLUE}Banner: $banner${NC}"
        else
            log "${GREEN}$port/$service_name: OPEN${NC}"
        fi
        
        # Add to results for further enumeration
        echo "$port:$service_name:$banner" >> /tmp/open_ports_$$
    else
        [[ "$VERBOSE" == true ]] && log "${RED}[-] $port/$service_name: CLOSED${NC}"
    fi
}

# Parallel port scanning
parallel_scan() {
    local ports=("$@")
    local pids=()
    local count=0
    
    for port in "${ports[@]}"; do
        if (( count >= THREADS )); then
            wait ${pids[0]}
            pids=("${pids[@]:1}")
            ((count--))
        fi
        
        check_port $port &
        pids+=($!)
        ((count++))
    done
    
    # Wait for remaining processes
    for pid in "${pids[@]}"; do
        wait $pid
    done
}

# Select port list based on scan type
select_ports() {
    case $SCAN_TYPE in
        "quick") echo "${QUICK_PORTS[@]}" ;;
        "full") echo "${FULL_PORTS[@]}" ;;
        "web") echo "${WEB_PORTS[@]}" ;;
        "database") echo "${DATABASE_PORTS[@]}" ;;
        *) echo "${QUICK_PORTS[@]}" ;;
    esac
}

# Main execution
main() {
    log "${BLUE}=== Enhanced Port Scanner for Pentesting ===${NC}"
    log "${BLUE}Target: $TARGET${NC}"
    log "${BLUE}Scan Type: $SCAN_TYPE${NC}"
    log "${BLUE}Timeout: ${TIMEOUT}s${NC}"
    log "${BLUE}Threads: $THREADS${NC}"
    [[ -n "$OUTPUT_FILE" ]] && log "${BLUE}Output: $OUTPUT_FILE${NC}"
    log ""
    
    # Initialize temp file for results
    > /tmp/open_ports_$$
    
    # Target reachability check
    if ping -c 1 -W $TIMEOUT "$TARGET" >/dev/null 2>&1; then
        log "${GREEN}[+] Target is reachable${NC}"
    else
        log "${YELLOW}[!] Target not responding to ping, continuing scan...${NC}"
    fi
    log ""
    
    # Get ports to scan
    local ports_to_scan=($(select_ports))
    log "${YELLOW}Scanning ${#ports_to_scan[@]} ports...${NC}"
    
    # Perform parallel scan
    parallel_scan "${ports_to_scan[@]}"
    
    log ""
    log "${BLUE}=== Scan Complete ===${NC}"
    
    # Summary and recommendations
    if [[ -s /tmp/open_ports_$$ ]]; then
        log "${GREEN}=== Open Ports Found ===${NC}"
        while IFS=: read -r port service banner; do
            log "${GREEN}Port $port ($service)${NC}"
            [[ -n "$banner" ]] && log "  ${BLUE}$banner${NC}"
        done < /tmp/open_ports_$$
        
        log ""
        log "${YELLOW}=== Next Steps Recommendations ===${NC}"
        
        # Provide specific enumeration suggestions
        while IFS=: read -r port service banner; do
            case $service in
                "FTP") log "${PURPLE}• FTP ($port): Try anonymous login, check for vulnerabilities${NC}" ;;
                "SSH") log "${PURPLE}• SSH ($port): Check for weak credentials, version vulnerabilities${NC}" ;;
                "HTTP"|"HTTPS"|"HTTP-Alt"|"HTTPS-Alt") log "${PURPLE}• Web ($port): Directory enumeration, vulnerability scanning${NC}" ;;
                "SMB") log "${PURPLE}• SMB ($port): Check for shares, null sessions, vulnerabilities${NC}" ;;
                "RDP") log "${PURPLE}• RDP ($port): Check for weak credentials, bluekeep vulnerability${NC}" ;;
                "MySQL"|"PostgreSQL"|"MSSQL") log "${PURPLE}• Database ($port): Check for default credentials, injection${NC}" ;;
            esac
        done < /tmp/open_ports_$$
    else
        log "${RED}No open ports found${NC}"
    fi
    
    # Cleanup
    rm -f /tmp/open_ports_$$
}

# Run main function
main
