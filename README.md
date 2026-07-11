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

## Key decisions
<div dir="rtl">
۱. پردازش به صورت تک پاس(برای اینکه مصرف حافظه و دسترسی به حافظه کاهش پیدا کند): تصمیم گرفتم تمام توابع کمکی از تابع parse_log_file صدا زده شوند تا فایل فقط یکبار خوانده شود و سرعت بالای برنامه حفظ شود؛ برای همین لیست‌ زمان‌هایی که ارور ۵۰۰ دارند را جمع‌آوری کردم و به عنوان آرگومان به تابع مربوطه فرستادم
<br>
۲. استفاده از argparse بجای استفاده از آرگومان‌های کتابخانه sys که مانع کرش برنامه در صورت عدم وجود آرگومان شود و انعطاف پذیری بالاتری در دریافت آرگومان‌ها نشان دهد.
<br>
۳. نمایش هیستوگرام با کاراکتر‌های ASCII بجای اسنفاده از کتابخانه matplotlib برای تجربه بهتر در سرور‌های بدون رابط گرافیکی
</div>

## Challenges and solutions
<div dir="rtl">
۱. تشخیص خطوط خراب فایل لاگ. با استفاده از رجکس و کتابخانه re و کمک از هوش‌مصنوعی و چندین نوبت آزمون و خطا به رجکسی رسیدم که ماه‌های سال و وضعیت‌ها و نوع ریکوئست‌ها و ... را به صورت کامل و فیلترشده بررسی و چک می‌کرد
</div>

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