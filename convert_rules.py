import re
import argparse

def parse_rule(line):
    try:
        # Extract the SID and revision number
        sid_rev_match = re.search(r'sid:(\d+); rev:(\d+);', line)
        if not sid_rev_match:
            raise ValueError("SID and revision not found in rule")

        sid = sid_rev_match.group(1)
        rev = sid_rev_match.group(2)
        sid_rev = f"{sid}_{rev}"

        # Extract the source IPs
        ip_match = re.search(r'^alert ip \[([^\]]+)\]', line)
        if not ip_match:
            raise ValueError("Source IPs not found in rule")

        src_ips = ip_match.group(1).split(',')

        # Assuming $HOME_NET eventually needs conversion or predefined values
        dst_ips = ['$HOME_NET']

        # Building the converted rule string
        converted_rule = f"Alert; {sid_rev}; ip([{', '.join(src_ips)}], [{', '.join(dst_ips)}])"
        return converted_rule
    except Exception as e:
        raise ValueError(f"Failed to parse rule: {e}")

def convert_rules(input_file, success_output_file, error_output_file):
    with open(input_file, 'r') as infile, \
         open(success_output_file, 'w') as success_out, \
         open(error_output_file, 'w') as error_out:

        for line in infile:
            line = line.strip()
            if not line or line.startswith('#'):  # Skip empty lines or comments
                continue

            try:
                converted_rule = parse_rule(line)
                success_out.write(converted_rule + '\n')
            except ValueError as e:
                error_out.write(line + '\n')
                print(f"Error: {e} - Rule: {line}")

def main():
    parser = argparse.ArgumentParser(description="Convert Suricata rules to custom format")
    parser.add_argument('input_file', help="Path to the input file containing Suricata rules")
    parser.add_argument('success_output_file', help="Path to the output file for successfully converted rules")
    parser.add_argument('error_output_file', help="Path to the output file for rules that couldn't be converted")

    args = parser.parse_args()

    convert_rules(args.input_file, args.success_output_file, args.error_output_file)

if __name__ == '__main__':
    main()
