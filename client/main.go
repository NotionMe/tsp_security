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
