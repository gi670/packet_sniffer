import socket
import struct
import textwrap
from datetime import datetime


TAB_1 = "    "
TAB_2 = "        "


# ============================================================
# GENERAL HELPERS
# ============================================================

def line():
    print("-" * 80)


def mac_addr(bytes_addr):
    return ":".join(f"{b:02x}" for b in bytes_addr)


def ipv4(addr):
    return ".".join(map(str, addr))


def format_multi_line(prefix, data, width=80):
    if isinstance(data, bytes):
        data = " ".join(f"{b:02x}" for b in data)

    size = max(10, width - len(prefix))

    return "\n".join(
        prefix + part
        for part in textwrap.wrap(data, size)
    )


# ============================================================
# ETHERNET
# ============================================================

def ethernet_frame(data):
    if len(data) < 14:
        return None

    dest_mac, src_mac, proto = struct.unpack(
        "!6s6sH",
        data[:14]
    )

    return (
        mac_addr(dest_mac),
        mac_addr(src_mac),
        socket.htons(proto),
        data[14:]
    )


# ============================================================
# IPv4
# ============================================================

def ipv4_packet(data):

    if len(data) < 20:
        return None

    version_header_length = data[0]

    version = version_header_length >> 4

    header_length = (version_header_length & 15) * 4

    if len(data) < header_length:
        return None

    ttl, proto, src, target = struct.unpack(
        "!8xBB2x4s4s",
        data[:20]
    )

    return (
        version,
        header_length,
        ttl,
        proto,
        ipv4(src),
        ipv4(target),
        data[header_length:]
    )


# ============================================================
# TCP
# ============================================================

def tcp_segment(data):

    if len(data) < 20:
        return None

    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack(
        "!HHLLH",
        data[:14]
    )

    offset = (offset_reserved_flags >> 12) * 4

    if len(data) < offset:
        return None

    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return (
        src_port,
        dest_port,
        sequence,
        acknowledgment,
        offset,
        flag_urg,
        flag_ack,
        flag_psh,
        flag_rst,
        flag_syn,
        flag_fin,
        data[offset:]
    )


# ============================================================
# UDP
# ============================================================

def udp_segment(data):

    if len(data) < 8:
        return None

    src_port, dest_port, size = struct.unpack(
        "!HH2xH",
        data[:8]
    )

    return (
        src_port,
        dest_port,
        size,
        data[8:]
    )


# ============================================================
# DNS
# ============================================================

def dns_packet(data):

    # DNS header = 12 bytes
    if len(data) < 12:
        return None

    transaction_id, flags, questions, answers, authority, additional = struct.unpack(
        "!HHHHHH",
        data[:12]
    )

    return {
        "transaction_id": transaction_id,
        "flags": flags,
        "questions": questions,
        "answers": answers,
        "authority": authority,
        "additional": additional,
        "payload": data[12:]
    }


def read_dns_name(data, offset=0):

    labels = []
    position = offset

    while position < len(data):

        length = data[position]

        # End of domain name
        if length == 0:
            position += 1
            break

        # DNS compression pointer
        if (length & 0xC0) == 0xC0:

            if position + 1 >= len(data):
                return ".".join(labels), position + 1

            pointer = ((length & 0x3F) << 8) | data[position + 1]

            name, _ = read_dns_name(data, pointer)

            labels.append(name)

            position += 2
            break

        # Invalid label length
        if length > 63:
            break

        position += 1

        if position + length > len(data):
            break

        label = data[position:position + length]

        labels.append(
            label.decode(
                "utf-8",
                errors="replace"
            )
        )

        position += length

    return ".".join(labels), position


def parse_dns_query(data):

    dns = dns_packet(data)

    if not dns:
        return None

    payload = dns["payload"]

    if dns["questions"] == 0:
        return dns, None, None

    domain, position = read_dns_name(
        payload,
        0
    )

    # QTYPE + QCLASS
    if position + 4 <= len(payload):

        qtype, qclass = struct.unpack(
            "!HH",
            payload[position:position + 4]
        )

    else:
        qtype = None
        qclass = None

    return dns, domain, qtype


def dns_query_type(qtype):

    types = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY"
    }

    return types.get(
        qtype,
        str(qtype)
    )


# ============================================================
# ICMP
# ============================================================

def icmp_packet(data):

    if len(data) < 4:
        return None

    icmp_type, code, checksum = struct.unpack(
        "!BBH",
        data[:4]
    )

    return (
        icmp_type,
        code,
        checksum,
        data[4:]
    )


# ============================================================
# PAYLOAD HELPERS
# ============================================================

def safe_decode_payload(payload):

    try:
        return payload.decode(
            "utf-8",
            errors="replace"
        )

    except Exception:
        return ""


def looks_like_http(payload_text):

    http_markers = (
        "GET ",
        "POST ",
        "PUT ",
        "DELETE ",
        "HEAD ",
        "OPTIONS ",
        "PATCH ",
        "HTTP/1.1",
        "HTTP/1.0",
        "Host:",
        "User-Agent:"
    )

    return any(
        payload_text.startswith(marker)
        or marker in payload_text
        for marker in http_markers
    )


# ============================================================
# TCP DISPLAY
# ============================================================

def print_tcp(
    src,
    target,
    payload,
    src_port,
    dest_port,
    sequence,
    acknowledgment,
    offset,
    flag_urg,
    flag_ack,
    flag_psh,
    flag_rst,
    flag_syn,
    flag_fin
):

    print(
        f"{TAB_1}[TCP] "
        f"{src}:{src_port} -> "
        f"{target}:{dest_port}"
    )

    print(
        f"{TAB_2}Sequence: {sequence}"
    )

    print(
        f"{TAB_2}Acknowledgment: {acknowledgment}"
    )

    print(
        f"{TAB_2}Header Length: {offset}"
    )

    flags = []

    if flag_urg:
        flags.append("URG")

    if flag_ack:
        flags.append("ACK")

    if flag_psh:
        flags.append("PSH")

    if flag_rst:
        flags.append("RST")

    if flag_syn:
        flags.append("SYN")

    if flag_fin:
        flags.append("FIN")

    print(
        f"{TAB_2}Flags: {', '.join(flags) if flags else 'None'}"
    )

    if payload:

        payload_text = safe_decode_payload(
            payload
        )

        print(
            f"{TAB_2}Payload length: {len(payload)} bytes"
        )

        if looks_like_http(payload_text):

            print(
                f"{TAB_2}[HTTP detected]"
            )

        preview = payload_text[:200]

        if preview.strip():

            print(
                f"{TAB_2}Payload preview:"
            )

            print(
                format_multi_line(
                    f"{TAB_2}    ",
                    preview
                )
            )


# ============================================================
# UDP DISPLAY
# ============================================================

def print_udp(
    src,
    target,
    payload,
    src_port,
    dest_port,
    size
):

    print(
        f"{TAB_1}[UDP] "
        f"{src}:{src_port} -> "
        f"{target}:{dest_port}"
    )

    print(
        f"{TAB_2}Length: {size}"
    )

    if payload:

        print(
            f"{TAB_2}Payload length: {len(payload)} bytes"
        )


# ============================================================
# ICMP DISPLAY
# ============================================================

def print_icmp(
    src,
    target,
    payload,
    icmp_type,
    code,
    checksum
):

    print(
        f"{TAB_1}[ICMP] "
        f"{src} -> {target}"
    )

    print(
        f"{TAB_2}Type: {icmp_type}"
    )

    print(
        f"{TAB_2}Code: {code}"
    )

    print(
        f"{TAB_2}Checksum: {checksum}"
    )

    if payload:

        print(
            f"{TAB_2}Payload length: {len(payload)} bytes"
        )


# ============================================================
# MAIN SNIFFER
# ============================================================

def main():

    try:

        conn = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.ntohs(3)
        )

    except PermissionError:

        print(
            "Permission denied."
        )

        print(
            "Run the sniffer with sudo."
        )

        return

    except OSError as error:

        print(
            f"Could not create raw socket: {error}"
        )

        return

    print(
        "Starting packet sniffer on Linux..."
    )

    print(
        "Use only on networks and systems you own "
        "or are authorized to monitor."
    )

    line()

    try:

        while True:

            raw_data, _ = conn.recvfrom(
                65535
            )

            timestamp = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            print(
                f"\n[{timestamp}]"
            )

            # ------------------------------------------------
            # Ethernet
            # ------------------------------------------------

            ethernet = ethernet_frame(
                raw_data
            )

            if not ethernet:
                continue

            (
                dest_mac,
                src_mac,
                eth_proto,
                data
            ) = ethernet

            print(
                f"[Ethernet] "
                f"{src_mac} -> {dest_mac} "
                f"Proto={eth_proto}"
            )

            # ------------------------------------------------
            # IPv4
            # ------------------------------------------------

            if eth_proto == 8:

                ip = ipv4_packet(
                    data
                )

                if not ip:
                    line()
                    continue

                (
                    version,
                    header_length,
                    ttl,
                    proto,
                    src,
                    target,
                    payload
                ) = ip

                print(
                    f"{TAB_1}[IPv4] "
                    f"{src} -> {target} "
                    f"Version={version} "
                    f"HeaderLen={header_length} "
                    f"TTL={ttl} "
                    f"Proto={proto}"
                )

                # ------------------------------------------------
                # ICMP
                # ------------------------------------------------

                if proto == 1:

                    icmp = icmp_packet(
                        payload
                    )

                    if icmp:

                        (
                            icmp_type,
                            code,
                            checksum,
                            icmp_data
                        ) = icmp

                        print_icmp(
                            src,
                            target,
                            icmp_data,
                            icmp_type,
                            code,
                            checksum
                        )

                # ------------------------------------------------
                # TCP
                # ------------------------------------------------

                elif proto == 6:

                    tcp = tcp_segment(
                        payload
                    )

                    if tcp:

                        (
                            src_port,
                            dest_port,
                            sequence,
                            acknowledgment,
                            offset,
                            flag_urg,
                            flag_ack,
                            flag_psh,
                            flag_rst,
                            flag_syn,
                            flag_fin,
                            tcp_data
                        ) = tcp

                        print_tcp(
                            src,
                            target,
                            tcp_data,
                            src_port,
                            dest_port,
                            sequence,
                            acknowledgment,
                            offset,
                            flag_urg,
                            flag_ack,
                            flag_psh,
                            flag_rst,
                            flag_syn,
                            flag_fin
                        )

                # ------------------------------------------------
                # UDP
                # ------------------------------------------------

                elif proto == 17:

                    udp = udp_segment(
                        payload
                    )

                    if udp:

                        (
                            src_port,
                            dest_port,
                            size,
                            udp_data
                        ) = udp

                        print_udp(
                            src,
                            target,
                            udp_data,
                            src_port,
                            dest_port,
                            size
                        )

                        # ========================================
                        # DNS
                        # ========================================

                        if (
                            src_port == 53
                            or dest_port == 53
                        ):

                            dns, domain, qtype = parse_dns_query(
                                udp_data
                            )

                            if dns:

                                print(
                                    f"{TAB_2}[DNS]"
                                )

                                print(
                                    f"{TAB_2}Transaction ID: "
                                    f"{dns['transaction_id']}"
                                )

                                print(
                                    f"{TAB_2}Questions: "
                                    f"{dns['questions']}"
                                )

                                print(
                                    f"{TAB_2}Answers: "
                                    f"{dns['answers']}"
                                )

                                print(
                                    f"{TAB_2}Authority: "
                                    f"{dns['authority']}"
                                )

                                print(
                                    f"{TAB_2}Additional: "
                                    f"{dns['additional']}"
                                )

                                if domain:

                                    print(
                                        f"{TAB_2}DNS Query: "
                                        f"{domain}"
                                    )

                                if qtype:

                                    print(
                                        f"{TAB_2}Query Type: "
                                        f"{dns_query_type(qtype)}"
                                    )

                # ------------------------------------------------
                # Other IPv4 protocols
                # ------------------------------------------------

                else:

                    print(
                        f"{TAB_1}[IPv4] "
                        f"Protocol {proto} "
                        f"is not currently decoded."
                    )

            else:

                print(
                    f"{TAB_1}Ethernet protocol "
                    f"{eth_proto} is not IPv4."
                )

            line()

    except KeyboardInterrupt:

        print(
            "\nStopping packet sniffer..."
        )

    finally:

        conn.close()


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":
    main()
