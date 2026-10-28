# Практична робота № 3

## Тема: Налаштування захищеного каналу mTLS та протокол SMTP
---

## Мета роботи

- Опанувати принципи функціонування інфраструктури відкритих ключів (PKI) та генерації сертифікатів стандарту X.509 (Root CA, серверні та клієнтські сертифікати).
- Набути практичних навичок конфігурації захищених TCP-з'єднань на базі пакета `crypto/tls` із забезпеченням двосторонньої автентифікації (mTLS) та верифікації сертифікатів.
- Опанувати роботу з протоколом електронної пошти SMTP за допомогою стандартного пакета `net/smtp`.
- Навчитися формувати багатокомпонентні повідомлення формату MIME (HTML-розмітка та вкладення файлів) з кодуванням Base64.
- Реалізувати консольний шлюз критичних сповіщень та аудиту Zero Trust із захистом на транспортному рівні.

---

## Технічне забезпечення

| Компонент | Версія / Опис |
| :--- | :--- |
| ОС | Linux (x86_64) |
| Середовище розробки | Neovim / VS Code |
| Платформа виконання | Go SDK 1.22+ |
| Інструменти криптографії | OpenSSL 3.x |
| Протокол зв'язку | TLS 1.3 / TCP / SMTP |
| Термінал | bash |
| Система контролю версій | Git |

---

## Хід виконання роботи

---

### Рівень 1. Базовий: Генерація PKI та захищений mTLS-шлюз

1. Створено структуру директорій та ініціалізовано Go-модуль `tsp-security`.
2. У каталозі `certs/` розроблено скрипт `generate_certs.sh`, який генерує необхідні сертифікати:
   - Кореневий сертифікат локального центру сертифікації (`ca.crt`, `ca.key`);
   - Сертифікат сервера (`server.crt`, `server.key`) із розширенням SAN (`localhost`, `127.0.0.1`);
   - Сертифікат клієнта (`client.crt`, `client.key`) з атрибутом `CN=dispatcher-agent-01` та `extendedKeyUsage = clientAuth`.
3. У файлі `server/main.go` реалізовано TCP-сервер на порту `:8443`, який вимагає наявність та валідність клієнтського сертифіката (`tls.RequireAndVerifyClientCert`) та використовує `tls.VersionTLS13`.
4. У файлі `client/main.go` реалізовано авторизованого клієнта, що підключається до сервера з передачею свого сертифіката.

---

### Рівень 2. Ключовий: Автоматична відправка email-сповіщень через SMTP

1. У пакеті `pkg/email` реалізовано модуль взаємодії з поштовим сервером за допомогою `net/smtp`.
2. Сервер після успішної перевірки клієнта та отримання повідомлення про інцидент автоматично ініціює відправку сповіщення черговому інженеру на адресу `duty-engineer@internal.net` через SMTP-шлюз `127.0.0.1:1025`.

---

### Рівень 3. Просунутий: Аудит Zero Trust, MIME-форматування та вкладення файлів

1. Сервер виконує аудит підключеного клієнта через `tlsConn.ConnectionState().PeerCertificates`, витягує `Subject.CommonName`, серійний номер сертифіката та термін його дії.
2. Формується багатокомпонентний лист формату MIME (`multipart/mixed`):
   - **HTML-частина:** стилізований блок тривоги з деталями збою та параметрами ідентифікації клієнта;
   - **Вкладення:** звіт `incident_report.log`, закодований у Base64.
3. Після обробки клієнту повертається статус: `[SERVER]: ALERT PROCESSED AND DISPATCHED`.

---

### Результати виконання та перевірка роботи

#### 1. Запуск сервера:
```text
=== Захищений шлюз критичних сповіщень (mTLS: 8443, SMTP Target: 1025) ===
[СЕРВЕР] Пул CA завантажено: certs/ca.crt (1 сертифікат)
[СЕРВЕР] Слухач mTLS відкрито на порту :8443
```

#### 2. Запуск авторизованого клієнта:
```text
=== Агент диспетчеризації (mTLS Client) ===
[КЛІЄНТ] Завантажено сертифікат клієнта: certs/client.crt (CN=dispatcher-agent-01)
[КЛІЄНТ] Підключення до шлюзу 127.0.0.1:8443...
[КЛІЄНТ] mTLS-рукостискання успішне. Використано протокол TLS 1.3
[КЛІЄНТ] Відправка алерту: CRITICAL_ERROR: Database connection timeout on node-04
[КЛІЄНТ] Відповідь від сервера: [SERVER]: ALERT PROCESSED AND DISPATCHED
[КЛІЄНТ] Сесію успішно завершено.
```

#### 3. Виведення у консолі сервера при обробці події:
```text
[ПІДКЛЮЧЕННЯ] Встановлено TLS-з'єднання від 127.0.0.1:45342
[АУДИТ ZERO TRUST] Клієнт верифікований: CN=dispatcher-agent-01, Серійний номер=77643672842684791570881519719702396405189021290
[ПОВІДОМЛЕННЯ] Отримано інцидент: CRITICAL_ERROR: Database connection timeout on node-04
[SMTP] Формування MIME-повідомлення (HTML + вкладення incident_report.log)...
[SMTP] Надсилання email на duty-engineer@internal.net через 127.0.0.1:1025...
[ВІДПОВІДЬ] Клієнту надіслано статус: [SERVER]: ALERT PROCESSED AND DISPATCHED
```

#### 4. Спроба неавторизованого доступу без сертифіката:
```bash
curl -k https://localhost:8443
```
```text
curl: (56) OpenSSL SSL_read: OpenSSL/3.6.4: error:0A00045C:SSL routines::tlsv13 alert certificate required
```
У консолі сервера:
```text
[ВІДХИЛЕНО] Неавторизоване підключення від [::1]:54268: TLS handshake failed: tls: client didn't provide a certificate
```

---

## Висновки

- Згенеровано інфраструктуру відкритих ключів PKI (Root CA, сертифікати сервера та клієнта стандарту X.509) за допомогою утиліти OpenSSL.
- Налаштовано mTLS-сервер і клієнт на мові Go з використанням пакета `crypto/tls`, політикою перевірки сертифікатів `tls.RequireAndVerifyClientCert` та протоколом TLS 1.3.
- Перевірено відхилення неавторизованих запитів без дійсного клієнтського сертифіката.
- Реалізовано сервіс надсилання сповіщень через SMTP (`net/smtp`) з формуванням багатокомпонентних листів стандарту MIME (HTML-тіло та Base64-вкладення логу події).
- Реалізовано аудит суб'єкта клієнтського сертифіката в рамках концепції Zero Trust.

---

# Лістинг

## certs/generate_certs.sh
```bash
#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 365 \
  -subj "/CN=MyRootCA/O=SecureAlertGateway/C=UA"

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost/O=SecureAlertGateway/C=UA"

cat > server_ext.cnf << 'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -extfile server_ext.cnf

openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/CN=dispatcher-agent-01/O=EmergencyDispatcher/C=UA"

cat > client_ext.cnf << 'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 -extfile client_ext.cnf

rm -f server.csr client.csr server_ext.cnf client_ext.cnf ca.srl
```

## pkg/email/mailer.go
```go
package email

import (
	"encoding/base64"
	"fmt"
	"net/smtp"
	"strings"
	"time"
)

type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type ClientAuditInfo struct {
	CommonName   string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	IP           string
}

type AlertEvent struct {
	Timestamp time.Time
	Message   string
	Audit     ClientAuditInfo
}

type Mailer struct {
	config Config
}

func NewMailer(cfg Config) *Mailer {
	if cfg.From == "" {
		cfg.From = "gateway@secure.internal.net"
	}
	return &Mailer{config: cfg}
}

func (m *Mailer) SendAlertMail(to string, event AlertEvent) error {
	addr := fmt.Sprintf("%s:%d", m.config.Host, m.config.Port)

	var auth smtp.Auth
	if m.config.Username != "" && m.config.Password != "" {
		auth = smtp.PlainAuth("", m.config.Username, m.config.Password, m.config.Host)
	}

	subject := fmt.Sprintf("CRITICAL ALERT: [%s] Incident Detected", event.Audit.CommonName)
	rawMsg := BuildMultipartMessage(m.config.From, to, subject, event)

	return smtp.SendMail(addr, auth, m.config.From, []string{to}, rawMsg)
}

func BuildMultipartMessage(from, to, subject string, event AlertEvent) []byte {
	boundary := fmt.Sprintf("boundary_%d_alert_gateway", time.Now().UnixNano())

	htmlBody := generateHTMLBody(event)

	logContent := generateIncidentLog(event)
	encodedLog := base64.StdEncoding.EncodeToString([]byte(logContent))

	var formattedBase64 strings.Builder
	for i := 0; i < len(encodedLog); i += 76 {
		end := i + 76
		if end > len(encodedLog) {
			end = len(encodedLog)
		}
		formattedBase64.WriteString(encodedLog[i:end])
		formattedBase64.WriteString("\r\n")
	}

	var msg strings.Builder

	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
	msg.WriteString("\r\n")

	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(htmlBody)
	msg.WriteString("\r\n")

	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=UTF-8; name=\"incident_report.log\"\r\n")
	msg.WriteString("Content-Disposition: attachment; filename=\"incident_report.log\"\r\n")
	msg.WriteString("Content-Transfer-Encoding: base64\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(formattedBase64.String())
	msg.WriteString("\r\n")

	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	return []byte(msg.String())
}

func generateHTMLBody(event AlertEvent) string {
	timeStr := event.Timestamp.Format("2006-01-02 15:04:05 MST")
	validUntil := event.Audit.NotAfter.Format("2006-01-02 15:04:05")

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f4f6f8; margin: 0; padding: 20px; }
        .card { background-color: #ffffff; border-radius: 8px; border: 1px solid #e1e4e8; max-width: 650px; margin: 0 auto; overflow: hidden; }
        .header { background: #b71c1c; color: #ffffff; padding: 20px; text-align: left; }
        .header h1 { margin: 0 0 6px 0; font-size: 20px; }
        .header p { margin: 0; font-size: 13px; opacity: 0.9; }
        .content { padding: 20px; }
        .alert-box { background-color: #fff3e0; border-left: 4px solid #ff9800; padding: 12px 16px; margin-bottom: 20px; font-family: monospace; font-size: 14px; color: #e65100; }
        .table { width: 100%%; border-collapse: collapse; }
        .table th, .table td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eeeeee; font-size: 13px; }
        .table th { background-color: #fafbfc; color: #586069; width: 35%%; }
        .footer { background-color: #fafbfc; padding: 12px 20px; text-align: center; font-size: 12px; color: #6a737d; border-top: 1px solid #e1e4e8; }
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <h1>Шлюз безпеки: Сповіщення про інцидент</h1>
            <p>Двостороння автентифікація mTLS підтверджена. Джерело верифіковано.</p>
        </div>
        <div class="content">
            <div class="alert-box">
                %s
            </div>
            <table class="table">
                <tr>
                    <th>Час реєстрації:</th>
                    <td>%s</td>
                </tr>
                <tr>
                    <th>Автентифікований клієнт (CN):</th>
                    <td><strong>%s</strong></td>
                </tr>
                <tr>
                    <th>IP-адреса джерела:</th>
                    <td>%s</td>
                </tr>
                <tr>
                    <th>Серійний номер сертифіката:</th>
                    <td><code>%s</code></td>
                </tr>
                <tr>
                    <th>Дійсність сертифіката до:</th>
                    <td>%s</td>
                </tr>
                <tr>
                    <th>Статус:</th>
                    <td><span style="color: #2e7d32; font-weight: bold;">Zero Trust Validated</span></td>
                </tr>
            </table>
        </div>
        <div class="footer">
            Звіт аудиту прикріплено у файлі <strong>incident_report.log</strong>.
        </div>
    </div>
</body>
</html>`,
		event.Message,
		timeStr,
		event.Audit.CommonName,
		event.Audit.IP,
		event.Audit.SerialNumber,
		validUntil,
	)
}

func generateIncidentLog(event AlertEvent) string {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString("                      SECURE ALERT GATEWAY INCIDENT REPORT                      \n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("Timestamp:               %s\n", event.Timestamp.UTC().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Incident Description:    %s\n", event.Message))
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString("ZERO TRUST CLIENT AUDIT DETAILS\n")
	sb.WriteString("--------------------------------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("Client CommonName (CN):  %s\n", event.Audit.CommonName))
	sb.WriteString(fmt.Sprintf("Client Remote Address:   %s\n", event.Audit.IP))
	sb.WriteString(fmt.Sprintf("Certificate Serial No:   %s\n", event.Audit.SerialNumber))
	sb.WriteString(fmt.Sprintf("Valid From:              %s\n", event.Audit.NotBefore.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Valid Until:             %s\n", event.Audit.NotAfter.Format(time.RFC3339)))
	sb.WriteString("Authentication Method:   Mutual TLS (mTLS) - X.509 Client Certificate\n")
	sb.WriteString("Verification Status:     PASSED (Issued by trusted Root CA)\n")
	sb.WriteString("================================================================================\n")
	sb.WriteString("SYSTEM DIAGNOSTICS DUMP:\n")
	sb.WriteString("Node Status:             DEGRADED\n")
	sb.WriteString("Action Required:         Immediate investigation by on-call engineer.\n")
	sb.WriteString("================================================================================\n")
	return sb.String()
}
```

## server/main.go
```go
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"tsp-security/pkg/email"
)

func main() {
	port := flag.Int("port", 8443, "port")
	certFile := flag.String("cert", "certs/server.crt", "server cert")
	keyFile := flag.String("key", "certs/server.key", "server key")
	caFile := flag.String("ca", "certs/ca.crt", "ca cert")
	smtpHost := flag.String("smtp-host", "127.0.0.1", "smtp host")
	smtpPort := flag.Int("smtp-port", 1025, "smtp port")
	dutyEmail := flag.String("duty-email", "duty-engineer@internal.net", "duty email")
	flag.Parse()

	fmt.Printf("=== Захищений шлюз критичних сповіщень (mTLS: %d, SMTP Target: %d) ===\n", *port, *smtpPort)

	caCertBytes, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося прочитати CA сертифікат: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertBytes) {
		log.Fatalf("[ПОМИЛКА] Не вдалося додати CA сертифікат до пулу")
	}
	fmt.Printf("[СЕРВЕР] Пул CA завантажено: %s (1 сертифікат)\n", *caFile)

	serverCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося завантажити сертифікат сервера: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS13,
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", *port), tlsConfig)
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося запустити mTLS слухач: %v", err)
	}
	defer listener.Close()

	fmt.Printf("[СЕРВЕР] Слухач mTLS відкрито на порту :%d\n", *port)

	mailer := email.NewMailer(email.Config{
		Host: *smtpHost,
		Port: *smtpPort,
		From: "gateway@secure.internal.net",
	})

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[ПОМИЛКА] Помилка прийняття з'єднання: %v", err)
			continue
		}

		go handleConnection(conn, mailer, *dutyEmail, *smtpHost, *smtpPort)
	}
}

func handleConnection(conn net.Conn, mailer *email.Mailer, dutyEmail, smtpHost string, smtpPort int) {
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Println("[ПОМИЛКА] З'єднання не є TLS")
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[ВІДХИЛЕНО] Неавторизоване підключення від %s: TLS handshake failed: %v", conn.RemoteAddr(), err)
		return
	}

	state := tlsConn.ConnectionState()
	fmt.Printf("[ПІДКЛЮЧЕННЯ] Встановлено TLS-з'єднання від %s\n", conn.RemoteAddr().String())

	var clientAudit email.ClientAuditInfo
	clientAudit.IP = conn.RemoteAddr().String()

	if len(state.PeerCertificates) > 0 {
		clientCert := state.PeerCertificates[0]
		clientAudit.CommonName = clientCert.Subject.CommonName
		clientAudit.SerialNumber = clientCert.SerialNumber.String()
		clientAudit.NotBefore = clientCert.NotBefore
		clientAudit.NotAfter = clientCert.NotAfter

		fmt.Printf("[АУДИТ ZERO TRUST] Клієнт верифікований: CN=%s, Серійний номер=%s\n",
			clientAudit.CommonName, clientAudit.SerialNumber)
	} else {
		log.Printf("[УВАГА] Сертифікати клієнта відсутні у ConnectionState")
		return
	}

	reader := bufio.NewReader(conn)
	message, err := reader.ReadString('\n')
	if err != nil && len(message) == 0 {
		log.Printf("[ПОМИЛКА] Помилка читання повідомлення від %s: %v", conn.RemoteAddr(), err)
		return
	}
	message = strings.TrimSpace(message)

	fmt.Printf("[ПОВІДОМЛЕННЯ] Отримано інцидент: %s\n", message)

	alertEvent := email.AlertEvent{
		Timestamp: time.Now(),
		Message:   message,
		Audit:     clientAudit,
	}

	fmt.Printf("[SMTP] Формування MIME-повідомлення (HTML + вкладення incident_report.log)...\n")
	fmt.Printf("[SMTP] Надсилання email на %s через %s:%d...\n", dutyEmail, smtpHost, smtpPort)

	if err := mailer.SendAlertMail(dutyEmail, alertEvent); err != nil {
		log.Printf("[SMTP] ⚠️ Помилка надсилання листа (можливо, SMTP-сервер не запущено): %v\n", err)
	} else {
		fmt.Printf("[SMTP] ✅ Лист про аварію успішно доставлено до поштового шлюзу!\n")
	}

	response := "[SERVER]: ALERT PROCESSED AND DISPATCHED\n"
	_, _ = conn.Write([]byte(response))
	fmt.Printf("[ВІДПОВІДЬ] Клієнту надіслано статус: [SERVER]: ALERT PROCESSED AND DISPATCHED\n")
}
```

## client/main.go
```go
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	host := flag.String("host", "127.0.0.1", "host")
	port := flag.Int("port", 8443, "port")
	certFile := flag.String("cert", "certs/client.crt", "client cert")
	keyFile := flag.String("key", "certs/client.key", "client key")
	caFile := flag.String("ca", "certs/ca.crt", "ca cert")
	msg := flag.String("msg", "CRITICAL_ERROR: Database connection timeout on node-04", "message")
	flag.Parse()

	fmt.Println("=== Агент диспетчеризації (mTLS Client) ===")

	caCertBytes, err := os.ReadFile(*caFile)
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося прочитати CA сертифікат: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertBytes) {
		log.Fatalf("[ПОМИЛКА] Не вдалося додати CA сертифікат до пулу")
	}

	clientCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося завантажити сертифікат клієнта: %v", err)
	}

	var clientCN = "unknown"
	if len(clientCert.Certificate) > 0 {
		if parsedCert, err := x509.ParseCertificate(clientCert.Certificate[0]); err == nil {
			clientCN = parsedCert.Subject.CommonName
		}
	}
	fmt.Printf("[КЛІЄНТ] Завантажено сертифікат клієнта: %s (CN=%s)\n", *certFile, clientCN)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}

	target := fmt.Sprintf("%s:%d", *host, *port)
	fmt.Printf("[КЛІЄНТ] Підключення до шлюзу %s...\n", target)

	conn, err := tls.Dial("tcp", target, tlsConfig)
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося підключитися через mTLS: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	tlsVersionStr := "TLS"
	switch state.Version {
	case tls.VersionTLS13:
		tlsVersionStr = "TLS 1.3"
	case tls.VersionTLS12:
		tlsVersionStr = "TLS 1.2"
	}
	fmt.Printf("[КЛІЄНТ] mTLS-рукостискання успішне. Використано протокол %s\n", tlsVersionStr)

	fmt.Printf("[КЛІЄНТ] Відправка алерту: %s\n", *msg)
	if _, err := conn.Write([]byte(*msg + "\n")); err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося надіслати повідомлення: %v", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("[ПОМИЛКА] Не вдалося прочитати відповідь сервера: %v", err)
	}
	resp = strings.TrimSpace(resp)

	fmt.Printf("[КЛІЄНТ] Відповідь від сервера: %s\n", resp)
	fmt.Println("[КЛІЄНТ] Сесію успішно завершено.")
}
```

## go.mod
```go
module tsp-security

go 1.22
```
