import sys, re, os, argparse, time
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

# LOG_PATTERN = re.compile(
#     r'(?P<ip>\S+)'
#     r'.*?'
#     r'\[(?P<timestamp>\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]\s+'
#     r'"(?P<method>GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/\d\.\d)"\s+'
#     r'(?P<status>\d+)\s+'
#     r'(?P<size>\S+)\s+'
#     r'"(?P<referrer>[^"]*)"\s+'
#     r'"(?P<user_agent>[^"]*)"$'
# )
LOG_PATTERN = re.compile(
    r'^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+-\s+-\s+\[(?P<timestamp>\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]\s+"(?P<method>GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/\d\.\d)"\s+(?P<status>\d{3})\s+(?P<size>\d+|\-)\s+"-"\s+"(?P<user_agent>[^"]*)"$'
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
    start_time = time.time()
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

        if total <= 0:
            print(f'{bcolors.FAIL}Log file {file_path} is corrupted or is not a log file.{bcolors.ENDC}')
            sys.exit(1)

        print(f'{bcolors.HEADER}Unique IPs: {len(UNIQUE_IPs)}{bcolors.ENDC}\n')
        print(f'{bcolors.OKBLUE}Total fine requests: {total}{bcolors.ENDC}')

        total_lines = total + corrupted
        corrupted_pct = round((corrupted / total_lines) * 100, 3) if total_lines > 0 else 0.0
        print(f'{bcolors.FAIL}Corrupted: {corrupted}{bcolors.ENDC}')
        print(f'{bcolors.FAIL}Corrupted percent: {corrupted_pct} %{bcolors.ENDC}\n')

        print(f'{bcolors.HEADER}Top 10 of most common endpoints:')
        for e in endpoint_counter.most_common(10):
            print(f'{bcolors.OKGREEN}endpoint: "{e[0]}" occurs {e[1]} times{bcolors.ENDC}')
        print()

        err_pct = round((error_counter / total) * 100, 3) if total > 0 else 0.0
        print(f'{bcolors.FAIL}Errors percent (4XX or 5XX): {err_pct}%{bcolors.ENDC}\n')

        print_histogram(hourly_counter)
        print()

        elapsed_time = time.time() - start_time
        print(f'{bcolors.OKGREEN}Elapsed time: {elapsed_time:.4f}{bcolors.ENDC}')

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='CLI tool to analyze web server access logs'
    )

    parser.add_argument(
        "log_file",
        help="Path to the access log file",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.log_file):
        print(f'{bcolors.FAIL}Log file {args.log_file} is not a valid file or does not exist!{bcolors.ENDC}')
        sys.exit(1)

    parse_log_file(args.log_file)