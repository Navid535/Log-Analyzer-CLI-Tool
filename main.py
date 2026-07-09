import sys, re


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)'
    r'.*?'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\S+)'
)

def parse_log_file(file_path):
    all_file_lines = 0
    total_logs = 0
    corrupted = 0

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()

            if not line:
                all_file_lines += 1
                continue

            match = LOG_PATTERN.match(line)
            if match:
                all_file_lines += 1
                total_logs += 1
                # if total_logs == 12:
                #     print(match.groupdict())
            else:
                all_file_lines += 1
                total_logs += 1
                corrupted += 1

        print(f'Corrupted: {corrupted}')
        print(f'Total: {total_logs}')
        print(f'Corrupted percent: {round((corrupted / total_logs) * 100, 3)}%')

if __name__ == '__main__':
    parse_log_file("access.log/access.log")