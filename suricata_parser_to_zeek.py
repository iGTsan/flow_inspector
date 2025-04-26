import re
import sys

# === Задай переменные! ===
VAR_MAP = {
    "$HOME_NET": "10.0.0.0/8",
    "$EXTERNAL_NET": "any",
    "$HTTP_PORTS": "80",
    "$SSH_PORTS": "22",
    "$SMTP_SERVERS": "10.0.0.0/8",
    "$SQL_SERVERS": "10.0.0.0/8",
    "$HTTP_SERVERS": "10.0.0.0/8",
    "$DNS_SERVERS": "10.0.0.0/8",
    # Добавлять свои переменные сюда по необходимости!
}

# --- Вспомогательные функции ---

def expand(var):
    if ':' in var:
        var = var.split(':')[0]
    if '!' in var:
        var = var.split('!')[1]
    if var[0] == '[':
        var = var[1:-1].split(',')[0]
    var = var.strip()
    if var in VAR_MAP:
        return VAR_MAP[var]
    return var

def parse_content(par):
    matches = re.findall(r'content:"([^"]+)"', par)
    out = []
    for m in matches:
        # Бинарная запись в Snort ("|41 42|")
        if m.startswith('|'):
            hexes = m.split('|')
            # print(hexes)
            for hx in hexes[1::2]:
                hx = hx.split()
                # print(hx)
                r = bytes([int(h,16) for h in hx if len(h) <= 2]).decode('latin1')
                if (len(r)):
                    out.append(bytes([int(h,16) for h in hx if len(h) <= 2]).decode('latin1'))
        else:
            out.append(m)
    return out

def parse_msg(par):
    m = re.search(r'msg:"([^"]+)"', par)
    return m.group(1) if m else 'No message!'

def parse_sid(par):
    m = re.search(r'sid:(\d+)', par)
    return 'snort_sid_' + m.group(1) if m else 'snort_sid_UNKNOWN'

def snort2zeek_ip(val):
    val = expand(val)
    return None if val == "any" else val

def snort2zeek_port(val):
    val = expand(val)
    if val == "any": return None
    # Перечисление портов в snort: "80 8080" → "80", Zeek signatures поддерживает только одно значение!
    ports = val.split(",")
    return ports[0].strip()
    
def parse_rule_line(line):
    # Пример: alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:...; content:"abc"; sid:1234;)
    m = re.match(r'alert\s+tcp\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s*\((.+)\)\s*', line)
    if not m: return None
    src_ip, src_port, dst_ip, dst_port, par = m.groups()
    result = {
        "src_ip": snort2zeek_ip(src_ip),
        "src_port": snort2zeek_port(src_port),
        "dst_ip": snort2zeek_ip(dst_ip),
        "dst_port": snort2zeek_port(dst_port),
        "params": par,
    }
    return result

def encode_zeek_regex(s):
    cbytes = s.encode('latin1')
    zhex = '\\x' + '\\x'.join(f"{b:02x}" for b in cbytes)
    return zhex

def process_rule(line):
    parsed = parse_rule_line(line)
    if not parsed: return
    par = parsed["params"]
    sid = parse_sid(par)
    msg = parse_msg(par)
    contents = parse_content(par)

    print(f'signature {sid} {{')
    print('    ip-proto == tcp')
    if parsed["src_ip"]:
        print(f'    src-ip == {parsed["src_ip"]}')
    if parsed["dst_ip"]:
        print(f'    dst-ip == {parsed["dst_ip"]}')
    if parsed["src_port"]:
        print(f'    src-port == {parsed["src_port"]}')
    if parsed["dst_port"]:
        print(f'    dst-port == {parsed["dst_port"]}')
    for c in contents:
        print(f'    payload /{encode_zeek_regex(c)}/')
    print(f'    event "Alert"\n}}')

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Использование: {sys.argv[0]} <snort_rules.txt>", file=sys.stderr)
        sys.exit(1)
    infile = sys.argv[1]
    with open(infile, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'): continue
            if line.startswith('alert tcp'):
                process_rule(line)
