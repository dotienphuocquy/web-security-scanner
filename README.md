# 🛡️ Web Security Scanner - Công cụ Kiểm thử Bảo mật Ứng dụng Web

## 📋 Giới thiệu

**Web Security Scanner** là công cụ tự động phát hiện và khai thác lỗ hổng bảo mật trong ứng dụng web, tập trung vào hai loại lỗ hổng phổ biến nhất:
- **SQL Injection (SQLi)** - Lỗ hổng cho phép kẻ tấn công can thiệp vào câu truy vấn cơ sở dữ liệu
- **Cross-Site Scripting (XSS)** - Lỗ hổng cho phép chèn mã JavaScript độc hại vào trang web

### ✨ Tính năng chính

- 🔍 **Tự động quét lỗ hổng**: Phát hiện SQL Injection và XSS
- 🎯 **Nhiều kỹ thuật kiểm thử**:
  - Error-based SQL Injection
  - Union-based SQL Injection
  - Boolean-based Blind SQL Injection
  - Time-based Blind SQL Injection
  - Reflected XSS
  - Stored XSS
- 📊 **Báo cáo chi tiết**: Export HTML và JSON
- 🖥️ **Giao diện đa dạng**: CLI và Web GUI
- 🎓 **Ứng dụng demo**: Web app có lỗ hổng để thực hành

---

## 📚 Kiến thức nền tảng

### 🔴 SQL Injection là gì?

**SQL Injection** là kỹ thuật tấn công cho phép kẻ tấn công chèn hoặc "inject" câu lệnh SQL độc hại vào câu truy vấn của ứng dụng. Khi ứng dụng không kiểm tra đầu vào người dùng đúng cách, kẻ tấn công có thể:
- Truy cập trái phép vào dữ liệu
- Sửa đổi hoặc xóa dữ liệu
- Bypass authentication (đăng nhập mà không cần mật khẩu)
- Thực thi lệnh hệ điều hành

**Ví dụ:**
```sql
-- Code gốc (vulnerable):
SELECT * FROM users WHERE username='$input' AND password='$password'

-- Input độc hại: admin' OR '1'='1
SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='$password'
-- Kết quả: Luôn trả về TRUE, bypass login
```

**Các loại SQL Injection:**
1. **Error-based**: Dựa vào thông báo lỗi SQL để khai thác
2. **Union-based**: Sử dụng UNION để lấy dữ liệu từ bảng khác
3. **Boolean-based Blind**: Dựa vào sự khác biệt TRUE/FALSE
4. **Time-based Blind**: Dựa vào độ trễ thời gian (SLEEP, WAITFOR)

### 🔵 Cross-Site Scripting (XSS) là gì?

**XSS** là lỗ hổng cho phép kẻ tấn công chèn mã JavaScript độc hại vào trang web. Khi người dùng khác truy cập, mã độc sẽ được thực thi trên trình duyệt của họ.

**Hậu quả:**
- Đánh cắp cookies và session tokens
- Chiếm quyền điều khiển tài khoản người dùng
- Phishing - Giả mạo giao diện web
- Phát tán malware

**Ví dụ:**
```html
<!-- Input độc hại: <script>alert(document.cookie)</script> -->

<!-- Code gốc (vulnerable): -->
<div>Search results for: <script>alert(document.cookie)</script></div>

<!-- Kết quả: Script được thực thi, hiển thị cookies -->
```

**Các loại XSS:**
1. **Reflected XSS**: Payload phản hồi ngay lập tức trong response
2. **Stored XSS**: Payload được lưu vào database và hiển thị cho nhiều người
3. **DOM-based XSS**: Khai thác qua JavaScript phía client

### 🛡️ Cách phòng chống

**SQL Injection:**
- ✅ Sử dụng Prepared Statements / Parameterized Queries
- ✅ Sử dụng ORM (Object-Relational Mapping)
- ✅ Validate và sanitize input
- ✅ Principle of Least Privilege cho database users
- ✅ Disable error messages chi tiết trên production

**XSS:**
- ✅ HTML Encoding cho tất cả user input
- ✅ Content Security Policy (CSP)
- ✅ HTTPOnly và Secure flags cho cookies
- ✅ Input validation và output encoding
- ✅ Sử dụng framework có built-in XSS protection

---

## 🚀 Cài đặt

### Yêu cầu hệ thống

- Python 3.7 trở lên
- pip (Python package manager)
- Hệ điều hành: Windows, Linux, macOS

### Bước 1: Clone hoặc tải project

```bash
git clone https://github.com/yourusername/web-security-scanner.git
cd web-security-scanner
```

### Bước 2: Cài đặt dependencies

```bash
pip install -r requirements.txt
```

**Packages được cài đặt:**
- `requests` - HTTP client
- `beautifulsoup4` - HTML parsing
- `flask` - Web framework cho GUI
- `colorama` - Colored terminal output
- `jinja2` - Template engine cho reports
- `lxml` - XML/HTML parser

### Bước 3: Kiểm tra cài đặt

```bash
python main.py --help
```

Nếu thấy menu help, cài đặt thành công! ✅

---

## 📖 Hướng dẫn sử dụng

### 🖥️ 1. Command Line Interface (CLI)

#### Scan SQL Injection

```bash
python main.py -u http://target.com/login.php?id=1 -t sqli
```

#### Scan XSS

```bash
python main.py -u http://target.com/search.php?q=test -t xss
```

#### Scan tất cả lỗ hổng

```bash
python main.py -u http://target.com -t all
```

#### Scan với custom output

```bash
python main.py -u http://target.com -t all -o my_scan_report
```

### 🌐 2. Web GUI

#### Khởi động Web GUI

```bash
python main.py --gui
```

Hoặc:

```bash
cd gui
python app.py
```

Truy cập: `http://127.0.0.1:5000`

**Tính năng Web GUI:**
- 📊 Dashboard trực quan
- ⏱️ Progress tracking real-time
- 📈 Statistics và charts
- 📥 Download báo cáo HTML/JSON
- 🎯 Scan history

---

## 🎯 Demo với Vulnerable App

### Khởi động Vulnerable Application

```bash
cd vulnerable_app
python app.py
```

App sẽ chạy tại: `http://127.0.0.1:8080`

### Test Credentials

| Username | Password    | Role  |
|----------|-------------|-------|
| admin    | admin123    | admin |
| user1    | password123 | user  |

### Các lỗ hổng có sẵn

#### 1. SQL Injection - Login Page

**URL:** `http://127.0.0.1:8080/login`

**Test payload:**
```
Username: admin' OR '1'='1
Password: anything
```

**Kết quả:** Bypass authentication thành công

#### 2. SQL Injection - Search

**URL:** `http://127.0.0.1:8080/search?q=test`

**Test payload:**
```
?q=' OR '1'='1
```

#### 3. SQL Injection - Profile

**URL:** `http://127.0.0.1:8080/profile?id=1`

**Test payload:**
```
?id=1 UNION SELECT 1,2,3,4,5
```

#### 4. Reflected XSS - Search

**URL:** `http://127.0.0.1:8080/search?q=test`

**Test payload:**
```
?q=<script>alert('XSS')</script>
```

#### 5. Stored XSS - Comments

**URL:** `http://127.0.0.1:8080/post/1`

**Test payload trong comment:**
```html
<img src=x onerror=alert('XSS')>
<script>alert(document.cookie)</script>
```

### Scan Vulnerable App

```bash
# Terminal 1: Chạy vulnerable app
cd vulnerable_app
python app.py

# Terminal 2: Chạy scanner
python main.py -u http://127.0.0.1:8080/login -t all
python main.py -u http://127.0.0.1:8080/search?q=test -t all
```

---

## 📁 Cấu trúc Project

```
kiem-thu-xam-nhap/
├── main.py                      # Entry point
├── config.py                    # Configuration
├── requirements.txt             # Dependencies
├── README.md                    # Tài liệu
│
├── scanners/                    # Scanner modules
│   ├── __init__.py
│   ├── sql_injection.py        # SQL Injection scanner
│   └── xss_scanner.py          # XSS scanner
│
├── payloads/                    # Payload collections
│   ├── __init__.py
│   ├── sql_payloads.py         # SQL Injection payloads
│   └── xss_payloads.py         # XSS payloads
│
├── utils/                       # Utilities
│   ├── __init__.py
│   ├── http_client.py          # HTTP client wrapper
│   ├── logger.py               # Logging utility
│   └── report_generator.py     # Report generation
│
├── gui/                         # Web GUI
│   ├── __init__.py
│   ├── app.py                  # Flask application
│   └── templates/
│       └── index.html          # Web interface
│
├── vulnerable_app/              # Demo vulnerable app
│   ├── __init__.py
│   ├── app.py                  # Flask app with vulnerabilities
│   └── templates/              # HTML templates
│       ├── vulnerable_index.html
│       ├── vulnerable_login.html
│       ├── vulnerable_search.html
│       ├── vulnerable_post.html
│       ├── vulnerable_dashboard.html
│       └── vulnerable_profile.html
│
└── reports/                     # Generated reports (auto-created)
    ├── scan_report.html
    └── scan_report.json
```

---

## ⚙️ Configuration

Chỉnh sửa `config.py` để thay đổi cài đặt:

```python
# Scanner settings
TIMEOUT = 10                    # Request timeout (seconds)
MAX_THREADS = 5                 # Concurrent threads

# SQL Injection
SQLI_DETECTION_TIMEOUT = 5      # Time-based SQLi delay
SQLI_MAX_PAYLOADS = 50          # Max payloads per parameter

# XSS
XSS_MAX_PAYLOADS = 30           # Max XSS payloads

# Reports
REPORT_DIR = "reports"
REPORT_FORMAT = "html"          # html, json, or both

# Logging
LOG_LEVEL = "INFO"              # DEBUG, INFO, WARNING, ERROR
LOG_FILE = "scanner.log"
```

---

## 📊 Báo cáo

### HTML Report

Báo cáo HTML bao gồm:
- 📈 Summary statistics
- 🎯 Vulnerability details với severity badges
- 💉 Payloads với syntax highlighting
- 💡 Recommendations
- 🎨 Professional design

**Vị trí:** `reports/report_name.html`

### JSON Report

Báo cáo JSON cho phép:
- 🔄 Integration với các công cụ khác
- 📊 Automated processing
- 📈 Trend analysis

**Vị trí:** `reports/report_name.json`

**Format:**
```json
{
  "scan_info": {
    "timestamp": "2025-12-08T10:30:00",
    "tool": "Web Security Scanner",
    "version": "1.0"
  },
  "statistics": {
    "total": 5,
    "high": 3,
    "medium": 2,
    "sqli": 3,
    "xss": 2
  },
  "vulnerabilities": [...]
}
```

---

## 🔬 Methodology

### SQL Injection Detection

1. **Parameter Discovery**: Tìm tất cả GET/POST parameters
2. **Error-based Testing**: Inject payloads gây lỗi SQL
3. **Union-based Testing**: Test UNION SELECT
4. **Boolean-based Testing**: So sánh TRUE/FALSE responses
5. **Time-based Testing**: Sử dụng SLEEP/WAITFOR DELAY
6. **Database Fingerprinting**: Xác định loại database

### XSS Detection

1. **Input Point Discovery**: Tìm forms và parameters
2. **Payload Injection**: Inject XSS payloads
3. **Response Analysis**: Kiểm tra payload trong response
4. **Context Detection**: Xác định HTML/JS/Attribute context
5. **Filter Bypass**: Test encoding và obfuscation
6. **Stored XSS Verification**: Re-fetch page để verify

---

## ⚠️ Disclaimer & Legal

### ⚡ CẢNH BÁO QUAN TRỌNG

```
┌─────────────────────────────────────────────────────────┐
│                    ⚠️  LƯU Ý PHÁP LÝ                     │
├─────────────────────────────────────────────────────────┤
│ • Chỉ sử dụng công cụ này trên hệ thống BẠN SỞ HỮU      │
│ • Phải có SỰ CHO PHÉP BẰNG VĂN BẢN trước khi scan       │
│ • KHÔNG scan website của người khác không có phép       │
│ • Vi phạm có thể dẫn đến hậu quả PHÁP LÝ NGHIÊM TRỌNG   │
│ • Tác giả KHÔNG chịu trách nhiệm về hành vi vi phạm     │
└─────────────────────────────────────────────────────────┘
```

### Mục đích sử dụng hợp pháp

✅ **Được phép:**
- Kiểm thử ứng dụng của chính bạn
- Penetration testing với sự cho phép
- Mục đích giáo dục và nghiên cứu
- Bug bounty programs (theo quy định)
- Security audit được ủy quyền

❌ **KHÔNG được phép:**
- Scan website mà không có phép
- Tấn công hệ thống của người khác
- Sử dụng cho mục đích bất hợp pháp
- Gây thiệt hại cho hệ thống
- Vi phạm Computer Fraud and Abuse Act (CFAA)

---

## 🎓 Educational Content

### Lab Exercises

#### Exercise 1: Basic SQL Injection
1. Khởi động vulnerable app
2. Truy cập `/login`
3. Thử bypass với: `admin' OR '1'='1`
4. Quan sát SQL query trong console
5. Chạy scanner để tự động phát hiện

#### Exercise 2: Union-based SQLi
1. Truy cập `/search?q=test`
2. Test: `test' UNION SELECT 1,2,3--`
3. Tìm số cột phù hợp
4. Extract data: `' UNION SELECT username,password,email FROM users--`

#### Exercise 3: Reflected XSS
1. Truy cập `/search?q=<script>alert(1)</script>`
2. Quan sát script execution
3. Thử bypass filters với encoding
4. Test payloads khác nhau

#### Exercise 4: Stored XSS
1. Login vào vulnerable app
2. Comment với payload: `<img src=x onerror=alert(1)>`
3. Reload page và quan sát
4. Hiểu về persistent XSS

### Study Resources

**SQL Injection:**
- OWASP SQL Injection Guide
- PortSwigger SQL Injection Labs
- DVWA (Damn Vulnerable Web Application)

**XSS:**
- OWASP XSS Guide
- XSS Game by Google
- PortSwigger XSS Labs

---

## 🐛 Troubleshooting

### Lỗi thường gặp

#### 1. ModuleNotFoundError

```bash
# Giải pháp: Cài đặt dependencies
pip install -r requirements.txt
```

#### 2. Connection Error

```bash
# Kiểm tra target URL có accessible không
curl http://target.com

# Kiểm tra firewall/proxy settings
```

#### 3. No vulnerabilities found

- ✓ Đảm bảo target URL đúng và accessible
- ✓ Target có thực sự vulnerable không?
- ✓ Thử với vulnerable app của project
- ✓ Kiểm tra logs trong `scanner.log`

#### 4. Scanner chạy chậm

```python
# Giảm số lượng payloads trong config.py
SQLI_MAX_PAYLOADS = 20
XSS_MAX_PAYLOADS = 15
```

---

## 🤝 Contributing

Contributions are welcome! 

### Cách contribute:
1. Fork repository
2. Tạo branch mới: `git checkout -b feature/new-feature`
3. Commit changes: `git commit -m "Add new feature"`
4. Push: `git push origin feature/new-feature`
5. Tạo Pull Request

### Areas for improvement:
- Thêm payload mới
- Support thêm loại vulnerabilities
- Tối ưu performance
- Improve reporting
- Add unit tests

---

## 📝 Changelog

### Version 1.0 (Current)
- ✅ SQL Injection scanner (Error, Union, Boolean, Time-based)
- ✅ XSS scanner (Reflected, Stored)
- ✅ CLI interface
- ✅ Web GUI
- ✅ HTML/JSON reports
- ✅ Vulnerable demo app
- ✅ Comprehensive documentation

---

## 📧 Contact & Support

**Author:** Security Research Team  
**Email:** security@example.com  
**GitHub:** https://github.com/yourusername/web-security-scanner

### Support
- 📖 Documentation: README.md
- 🐛 Bug reports: GitHub Issues
- 💡 Feature requests: GitHub Discussions

---

## 📜 License

MIT License

Copyright (c) 2025 Web Security Scanner

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 🌟 Acknowledgments

- OWASP Foundation for security guidelines
- PortSwigger Web Security Academy
- Python community for excellent libraries
- Security researchers worldwide

---

## 📚 References

1. **OWASP Top 10**: https://owasp.org/www-project-top-ten/
2. **SQL Injection**: https://owasp.org/www-community/attacks/SQL_Injection
3. **XSS**: https://owasp.org/www-community/attacks/xss/
4. **Web Security Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/

---

<div align="center">

**⚡ Made with ❤️ for Security Testing**

**🔒 Stay Safe, Test Responsibly 🔒**

</div>
