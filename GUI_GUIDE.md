# 🚀 Hướng dẫn chạy Web GUI

## Bước 1: Khởi động Vulnerable App

Mở terminal thứ nhất và chạy:

```powershell
cd d:\vscode\ky7\kiem-thu-xam-nhap
python -c "from vulnerable_app.app import start_vulnerable_app; start_vulnerable_app()"
```

Đợi cho đến khi thấy:
```
 * Running on http://127.0.0.1:8080
```

**✅ Vulnerable app đang chạy trên port 8080**

---

## Bước 2: Khởi động GUI

Mở terminal thứ hai và chạy:

```powershell
cd d:\vscode\ky7\kiem-thu-xam-nhap  
python main.py --gui
```

Đợi cho đến khi thấy:
```
 * Running on http://127.0.0.1:5000
```

**✅ GUI đang chạy trên port 5000**

---

## Bước 3: Test Scanner

1. **Mở browser** và truy cập: http://127.0.0.1:5000

2. **Nhập URL để scan**:
   ```
   http://127.0.0.1:8080/login
   ```

3. **Chọn scan type**: All Vulnerabilities

4. **Click "Start Scan"** 🚀

5. **Xem kết quả**: Scanner sẽ tự động phát hiện lỗ hổng!

---

## ⚠️ Lưu ý quan trọng:

### Nếu scan không phát hiện lỗ hổng:

**Kiểm tra 1**: Vulnerable app có đang chạy không?
```powershell
# Test bằng curl
curl http://127.0.0.1:8080
```

Nếu thấy response HTML => App đang chạy ✅
Nếu connection refused => App chưa chạy ❌

**Kiểm tra 2**: URL đúng chưa?
- ✅ ĐÚNG: `http://127.0.0.1:8080/login`
- ❌ SAI: `https://127.0.0.1:8080/login` (https)
- ❌ SAI: `http://localhost:8080/login` (dùng localhost thay vì 127.0.0.1)
- ❌ SAI: `http://127.0.0.1:8080` (thiếu /login)

**Kiểm tra 3**: Xem console log của GUI
- Trong terminal chạy GUI, sẽ có output:
  ```
  [GUI] Starting scan...
  [GUI] SQL Injection scan found X vulnerabilities
  [GUI] XSS scan found Y vulnerabilities
  ```

---

## 🧪 Test nhanh bằng CLI (nếu GUI không hoạt động):

```powershell
# Test với CLI trực tiếp  
python main.py -u http://127.0.0.1:8080/login -t all

# Hoặc dùng test script
python test_scanner.py
```

Nếu CLI hoạt động => Scanner OK, vấn đề ở GUI
Nếu CLI không hoạt động => Vulnerable app chưa chạy

---

## 📊 Kết quả mong đợi:

Scanner sẽ phát hiện:
- 2 SQL Injection ở login form (username & password)
- Tổng cộng 4-7 lỗ hổng tùy URL được scan

---

## 🆘 Nếu vẫn gặp lỗi:

1. **Chạy test script đầy đủ**:
   ```powershell
   python test_scanner.py
   ```
   
2. **Check GUI log** trong terminal GUI để xem error messages

3. **Restart cả 2 services**: Ctrl+C rồi start lại

4. **Kiểm tra port conflicts**: 
   ```powershell
   netstat -ano | findstr :8080
   netstat -ano | findstr :5000
   ```
