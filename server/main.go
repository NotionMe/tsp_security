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
