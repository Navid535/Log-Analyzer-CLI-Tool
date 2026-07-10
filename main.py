import sys, re
from collections import Counter

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)'
    r'.*?'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)

UNIQUE_IPs = set()
endpoint_counter = Counter()
hourly_counter = Counter()


def print_histogram(hours):
    max_value = max(hours.values())
    max_length = 50

    print(f'{bcolors.HEADER}Hourly Traffic Distribution:{bcolors.ENDC}')

    for h in range(24):
        hour_str = f"{h:02d}"
        count = hours.get(hour_str, 0)
        bar_length = int((count / max_value) * max_length) if max_value > 0 else 0
        bar = "█" * bar_length

        print(f'Hour {hour_str}: {count:6d} | {bar}')


def parse_log_file(file_path):
    all_file_lines = 0
    total = 0
    corrupted = 0
    error_counter = 0

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()

            if not line:   # empty line
                all_file_lines += 1
                continue

            match = LOG_PATTERN.match(line) # compare with regex

            if match:
                all_file_lines += 1
                total += 1

                UNIQUE_IPs.add(match.groupdict()['ip'])
                endpoint_counter[match.groupdict()['path']] += 1

                # 'timestamp': '01/Jun/2026:09:35:50 +0000'
                hour = match.groupdict()['timestamp'].split(':')[1]
                hourly_counter[hour] += 1

                # Requests with 4xx or 5xx status code
                if match.groupdict()['status'].startswith('4') or match.groupdict()['status'].startswith('5'):
                    error_counter += 1



            else:
                all_file_lines += 1
                corrupted += 1

        print(f'{bcolors.HEADER}Unique IPs: {len(UNIQUE_IPs)}{bcolors.ENDC}\n')
        print(f'{bcolors.OKBLUE}Total fine requests: {total}{bcolors.ENDC}')
        print(f'{bcolors.FAIL}Corrupted: {corrupted}{bcolors.ENDC}')
        print(f'{bcolors.FAIL}Corrupted percent: {round((corrupted / (total + corrupted)) * 100, 3)} %{bcolors.ENDC}\n')
        print(f'{bcolors.HEADER}Top 10 of most common endpoints:')
        for e in endpoint_counter.most_common(10):
            print(f'{bcolors.OKGREEN}endpoint: "{e[0]}" occurs {e[1]} times{bcolors.ENDC}')
        print()
        print(f'{bcolors.FAIL}Errors percent (4XX or 5XX): {round(error_counter / total * 100, 3)}%{bcolors.ENDC}\n')
        print_histogram(hourly_counter)

if __name__ == '__main__':
    print(sys.argv)
    # parse_log_file("access.log/access.log")