import sys
import re
import pprint

any = "[any]"

eventMap = {
    "alert": "Alert",
    "drop": "Alert",
}

def gen_event(rule):
    event = rule["Event"]
    if event in eventMap:
        return eventMap[event]
    print("unknown event", event)
    # return event

def gen_header(rule):
    return gen_event(rule) + "; " + rule["sid"] + "_" + rule["rev"] + ";"

def convert_ip(ip):
    if ip[0] == '[':
        ips = list(map(convert_ip, ip[1:-1].split(',')))
        ips2 = []
        for ip2 in ips:
            if ip2[0] == '[':
                ips2.append(ip2[1:-1])
            else:
                ips2.append(ip2)
        ip = f"[{','.join(ips2)}]"
    if ip == "$HOME_NET" or ip == "$HTTP_SERVERS" or ip == "$SQL_SERVERS" or ip == "$SMTP_SERVERS" or ip == "$DNS_SERVERS":
        return "[192.168.0.0/24,10.0.0.0/16]"
    if ip == "$EXTERNAL_NET" or ip == "any":
        return any
    return ip

def convert_port(port):
    if port[0] == '[':
        return convert_port(port[1:-1].split(',')[-1])
    if port == "$HTTP_PORTS":
        return "[80]"
    if port == "$SSH_PORTS":
        return "[22]"
    if port == "any":
        return any
    return f"[{port}]"

def ip_parser(rule):
    res = ""
    src_ip = convert_ip(rule["src_ip"])
    dst_ip = convert_ip(rule["dst_ip"])
    if src_ip != any or dst_ip != any:
        res += f"ip({src_ip},{dst_ip}); "
    
    return res

def content_parser(rule):
    res = ""
    if "content" in rule:
        contents = rule["content"]
        if isinstance(contents, list):
            for content in contents:
                res += f"content({rule['protocol']}, {content}); "
        else:
            res += f"content({rule['protocol']}, {contents}); "
    return res

def tcp_parser(rule):
    res = ip_parser(rule)
    src_port = convert_port(rule["src_port"])
    dst_port = convert_port(rule["dst_port"])
    # if src_ip or dst_ip:
    if src_port != any or dst_port != any:
        res += f"tcp({src_port}, {dst_port}); "
    res += content_parser(rule)
    
    return res

parserMap = {
    "ip": ip_parser,
    "tcp": tcp_parser
}

def parse_suricata_rule(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Основная часть до скобки и скобочная часть
    if '(' not in line:
        return None
    main_part, paren = line.split('(', 1)
    paren = paren.rstrip(')')

    tokens = main_part.strip().split()
    if '->' in tokens:
        arrow_idx = tokens.index('->')
    elif '>' in tokens:
        arrow_idx = tokens.index('>')
    else:
        return None

    dct = {
        'Event': tokens[0],
        'protocol': tokens[1],
        'src_ip': tokens[2],
        'src_port': tokens[3],
        'direction': tokens[arrow_idx],
        'dst_ip': tokens[arrow_idx+1],
        'dst_port': tokens[arrow_idx+2],
    }

    # Поля в скобках, формата key:value или key:"..."; с учетом кавычек
    # Используем re.findall хватает и кавычки, и без них
    fields = re.findall(r'(\w+):\s*("([^"]*)"|[^;"]*)', paren)
    for key, fullval, quotedval in fields:
        value = quotedval if quotedval else fullval.strip().strip('"')
        # Несколько таких же ключей превращаем в список
        if key in dct:
            if isinstance(dct[key], list):
                dct[key].append(value)
            else:
                dct[key] = [dct[key], value]
        else:
            dct[key] = value
    return dct

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 parse_suricata.py <rulesfile>")
        sys.exit(1)

    filename = sys.argv[1]
    with open(filename, encoding='utf-8') as f:
        for line in f:
            parsed = parse_suricata_rule(line)
            if parsed["protocol"] in parserMap:
                rule = parserMap[parsed["protocol"]](parsed)
                if rule:
                    print(gen_header(parsed), rule)
            # if parsed["protocol"] == "ip" or parsed["protocol"] == "tcp" or parsed["protocol"] == "udp":
            #     if parsed:
            #         pprint.pprint(parsed)
            #         print('-'*40)

if __name__ == "__main__":
    main()
