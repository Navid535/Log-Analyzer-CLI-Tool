import sys, re, os, argparse, time, gzip, json
from collections import Counter
from datetime import datetime, timedelta


# colorize output (copied from Stackoverflow.com)
class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


# regex for checking log lines
LOG_PATTERN = re.compile(
    r'^(?P<ip>(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))\s+-\s+-\s+\[(?P<timestamp>\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\]\s+"(?P<method>GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)\s+(?P<path>\S+)\s+(?P<protocol>HTTP/\d\.\d)"\s+(?P<status>\d{3})\s+(?P<size>\d+|\-)\s+"-"\s+"(?P<user_agent>[^"]*)"$'
)

UNIQUE_IPs = set()
endpoint_counter = Counter()
hourly_counter = Counter()
suspicious_IPs = Counter()


def print_histogram(hours):
    max_value = max(hours.values())
    max_length = 50

    print(f"{bcolors.HEADER}Hourly Traffic Distribution:{bcolors.ENDC}")

    for h in range(24):
        hour_str = f"{h:02d}"
        count = hours.get(hour_str, 0)
        bar_length = int((count / max_value) * max_length) if max_value > 0 else 0
        bar = "█" * bar_length

        print(f"Hour {hour_str}: {count:6d} | {bar}")


def find_suspect(suspicious_counter, threshold=20):
    suspects = {
        ip: count for ip, count in suspicious_counter.items() if count >= threshold
    }

    if not suspects:
        print(
            f"{bcolors.OKGREEN}No suspects with 401/login requests detected.{bcolors.ENDC}"
        )
        return

    sorted_suspects = sorted(suspects.items(), key=lambda item: item[1], reverse=True)
    for ip, count in sorted_suspects[:10]:
        print(
            f"{bcolors.FAIL}IP: {ip:<15} | failed attempts / login hits {count}{bcolors.ENDC}"
        )
    print()


def find_error_time_range(error_timestamp):
    if not error_timestamp:
        return None

    error_timestamp.sort()
    window_duration = timedelta(minutes=60)
    max_errors = 0
    best_window_start = error_timestamp[0]
    best_window_end = error_timestamp[0]

    left = 0
    for right in range(len(error_timestamp)):
        while error_timestamp[right] - error_timestamp[left] > window_duration:
            left += 1

        current_error_count = right - left + 1

        if current_error_count > max_errors:
            max_errors = current_error_count
            best_window_start = error_timestamp[left]
            best_window_end = error_timestamp[right]

    return {
        "start": best_window_start.strftime("%m/%d/%Y:%H:%M:%S"),
        "end": best_window_end.strftime("%m/%d/%Y:%H:%M:%S"),
        "total_errors": max_errors,
    }


def parse_log_file(
    file_path,
    json_output=False,
    end_points_number=10,
    filter_date=None,
    filter_status=None,
    show_suspects=False,
    show_downtime=False,
):
    start_time = time.time()
    total = 0
    not_included = 0
    corrupted = 0
    error_counter = 0
    error_timestamp_for_downtime = []

    start_dt, end_dt = None, None
    if filter_date:
        try:
            start_dt = datetime.strptime(filter_date[0], "%d/%b/%Y")
            end_dt = datetime.strptime(filter_date[1], "%d/%b/%Y")
        except ValueError:
            print(
                f"{bcolors.FAIL}Error: Invalid date format. Please use DD/Mon/YYYY (e.g., 01/Jun/2026).{bcolors.ENDC}"
            )
            sys.exit(1)

    open_func = gzip.open if file_path.endswith(".gz") else open
    open_mode = "rt" if file_path.endswith(".gz") else "r"

    with open_func(file_path, open_mode) as f:
        for line in f:
            line = line.strip()

            if not line:  # empty line
                continue

            match = LOG_PATTERN.match(line)  # compare with regex

            if match:
                # 'timestamp': '01/Jun/2026:09:35:50 +0000'
                full_timestamp = match.groupdict()["timestamp"]
                date = full_timestamp.split(":")[0]
                hour = full_timestamp.split(":")[1]
                status = match.groupdict()["status"]
                path = match.groupdict()["path"]
                ip = match.groupdict()["ip"]

                if (status == "401") or ("login" in path.lower()):
                    suspicious_IPs[ip] += 1

                if show_downtime and status.startswith("5"):
                    timestamp = full_timestamp.split(" ")[0]
                    dt = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S")
                    error_timestamp_for_downtime.append(dt)

                if filter_status and status != filter_status:
                    not_included += 1
                    continue

                if filter_date:
                    current_log_date = datetime.strptime(date, "%d/%b/%Y")
                    if not (start_dt <= current_log_date <= end_dt):
                        not_included += 1
                        continue

                hourly_counter[hour] += 1
                total += 1

                UNIQUE_IPs.add(match.groupdict()["ip"])
                endpoint_counter[match.groupdict()["path"]] += 1

                # Requests with 4xx or 5xx status code
                if match.groupdict()["status"].startswith("4") or match.groupdict()[
                    "status"
                ].startswith("5"):
                    error_counter += 1

            else:
                corrupted += 1

        if total <= 0 and not_included <= 0:
            if json_output:
                print(
                    json.dumps(
                        {
                            "error": f"Log file {file_path} is corrupted or is not a log file"
                        },
                        indent=4,
                    )
                )
            else:
                print(
                    f"{bcolors.FAIL}Log file {file_path} is corrupted or is not a log file.{bcolors.ENDC}"
                )
            sys.exit(1)
        elif total <= 0 < not_included:
            if json_output:
                print(
                    json.dumps(
                        {
                            "error": f"Log file {file_path} has no record with your filters"
                        },
                        indent=4,
                    )
                )
            else:
                print(
                    f"{bcolors.FAIL}Log file {file_path} has no record with your filters.{bcolors.ENDC}"
                )
            sys.exit(1)

        total_lines = total + corrupted
        corrupted_pct = (
            round((corrupted / total_lines) * 100, 3) if total_lines > 0 else 0.0
        )
        err_pct = round((error_counter / total) * 100, 3) if total > 0 else 0.0

        if json_output:
            output_data = {
                "unique_IPs": len(UNIQUE_IPs),
                "total_fine_requests": total,
                "corrupted_requests": corrupted,
                "corrupted_percentage": corrupted_pct,
                "top_endpoints": [
                    {"endpoint": e[0], "count": e[1]}
                    for e in endpoint_counter.most_common(end_points_number)
                ],
                "error_percent": err_pct,
                "hourly_distribution": {
                    f"{h:02d}": hourly_counter.get(f"{h:02d}", 0) for h in range(24)
                },
                "elapsed_time": time.time() - start_time,
            }

            if show_suspects:
                output_data["suspicious_ips"] = [
                    {"ip": k, "count": v} for k, v in suspicious_IPs.most_common(10)
                ]

            if show_downtime:
                output_data["critical_downtime_window"] = find_error_time_range(
                    error_timestamp_for_downtime
                )
            print(json.dumps(output_data, indent=4))

        else:
            print(f"{bcolors.HEADER}Unique IPs: {len(UNIQUE_IPs)}{bcolors.ENDC}\n")
            print(f"{bcolors.OKBLUE}Total fine requests: {total}{bcolors.ENDC}")

            print(f"{bcolors.FAIL}Corrupted: {corrupted}{bcolors.ENDC}")
            print(f"{bcolors.FAIL}Corrupted percent: {corrupted_pct} %{bcolors.ENDC}\n")

            print(f"{bcolors.HEADER}Top {end_points_number} of most common endpoints:")
            for e in endpoint_counter.most_common(end_points_number):
                print(
                    f'{bcolors.OKGREEN}endpoint: "{e[0]}"  count: {e[1]} times{bcolors.ENDC}'
                )
            print()

            print(
                f"{bcolors.FAIL}Errors percent (4XX or 5XX): {err_pct}%{bcolors.ENDC}\n"
            )

            print_histogram(hourly_counter)
            print()

            if show_suspects:
                find_suspect(suspicious_IPs, threshold=10)

            if show_downtime:
                downtime_data = find_error_time_range(error_timestamp_for_downtime)
                if downtime_data:
                    print(
                        f"{bcolors.HEADER}\nCritical 5xx error window found in the log file.{bcolors.ENDC}"
                    )
                    print(
                        f"{bcolors.FAIL}[{downtime_data['start']}] to [{downtime_data['end']}]{bcolors.ENDC}"
                    )
                    print(
                        f"Total 5XX errors in this 60-minute window: {bcolors.WARNING}{downtime_data['total_errors']}{bcolors.ENDC} errors"
                    )
                else:
                    print(
                        f"{bcolors.OKGREEN}No 5XX errors found in the log file.{bcolors.ENDC}"
                    )

            elapsed_time = time.time() - start_time
            print(f"{bcolors.OKGREEN}Elapsed time: {elapsed_time:.4f}{bcolors.ENDC}")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="CLI tool to analyze web server access logs"
    )

    parser.add_argument(
        "log_file",
        help="Path to the access log file",
    )

    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Print the output in JSON format instead of plain text",
        default=False,
    )

    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of most common endpoints to display",
    )

    parser.add_argument(
        "--date",
        nargs=2,
        metavar=("START", "END"),
        help="Filter logs by a specific date range (DD/MM/YYYY DD/MM/YYYY)",
    )

    parser.add_argument(
        "--status",
        help="Filter logs by a specific status (e.g. '403' or '200')",
    )

    parser.add_argument(
        "--downtime", action="store_true", help="Find time range with most 5xx errors"
    )

    parser.add_argument(
        "--suspects",
        action="store_true",
        help="Detect suspicious IP with 401 or login high activity",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.log_file):
        print(
            f"{bcolors.FAIL}Log file {args.log_file} is not a valid file or does not exist!{bcolors.ENDC}"
        )
        sys.exit(1)

    parse_log_file(
        args.log_file,
        json_output=args.json,
        end_points_number=args.top,
        filter_date=args.date,
        filter_status=args.status,
        show_suspects=args.suspects,
        show_downtime=args.downtime,
    )
