# Log Analyzer CLI Tool
ابزار خط فرمان برای آنالیز، فیلتر و استخراج بازه‌های بحرانی از فایل‌های لاگ وب‌سرور


از آنجایی که از کتابخانه‌های استاندارد استفاده شده نیازی به استفاده از محیط مجازی و نصب کتابخانه‌های خارجی نیست


## How to run
اجرای برنامه به صورت پیش‌فرض:
```shell
    python main.py <log_file_path>
```
(امکان استفاده از فایل‌های فشرده .gz)

تنظیم تعداد اندپوینت‌های برتر نمایش داده شده:
```shell
    python main.py <log_file_path> --top N
```

اجرای برنامه و خروجی به صورت جیسون:
```shell
    python main.py <log_file_path> -j 
```
or
```shell
    python main.py <log_file_path> --json
```

فیلتر بازه‌زمانی:
```shell
    python main.py <log_file_path> --date STARTDATE ENDDATE
```
مثلا:
```shell
    python main.py access.log --date 01/Jun/2026 05/Jun/2026
```

فیلتر وضعیت:
```shell
    python main.py <log_file_path> --status STATUS
```

نمایش مدت‌زمانی که سرور در آن بازه بیشترین وضعیت 5xx را خروجی داده است:
```shell
    python main.py <log_file_path> --downtime
```

نمایش آیپی‌های مشکوک(بیشترین ریکوئست لاگین و وضعیت ۴۰۱)
```shell
    python main.py <log_file_path> --suspects
```


## Libraries
1. **sys** for handling system exits and error code
2. **re** for checking Log file lines correction
3. **os** for file path validation
4. **time** for calculating run time
5. **argparse** reading arguments from command line
6. **gzip** for opening .gz files
7. **json** for generating JSON output
8. **Counter** for counting IPs, suspect IPs and showing Histogram
9. **datetime** for get date and time from log strings
10. **timedelta** windows size configuration for checking error durations
