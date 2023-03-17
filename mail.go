package main

import (
	"bytes"
	"fmt"
	"log"
	"net/mail"
	"net/smtp"
	"regexp"
	"strings"
)

type mailConfig struct {
	Domain     string   `yaml:"domain"`
	SmtpServer string   `yaml:"smtpServer"`
	ErrorPath  string   `yaml:"errorPath"`
	AlertTo    []string `yaml:"alertTo"`
	AlertFrom  string   `yaml:"alertFrom"`
	VirusEmail string   `yaml:"virusEmail"`
}

type mailHeaders struct {
	to    []string
	from  string
	virus string
}

func (mailCfg *mailConfig) deliverMail(key string, msg []byte) error {
	headers, err := getMailHeaders(msg, mailCfg.Domain)
	if err == nil {
		err = smtp.SendMail(mailCfg.SmtpServer, nil, headers.from, headers.to, msg)
	}
	if err != nil {
		if headers.virus == "FAIL" {
			err = fmt.Errorf("%v\nTHIS EMAIL FAILED SES VIRUS SCAN", err)
		}
		_, filename, _ := strings.Cut(key, "/")
		err = fmt.Errorf("failed to deliver message: %v\n"+
			"writing decrypted data to %s/%s", err, mailCfg.ErrorPath, filename)
		if err2 := writeFile(mailCfg.ErrorPath, filename, msg); err2 != nil {
			// Staying with %w for now versus errors.Join() because
			// Unwrap does not work with Join presently.
			err = fmt.Errorf("%w\n%v", err, err2)
		}
	} else if headers.virus == "FAIL" && mailCfg.VirusEmail != "" {
		mailCfg.sendAlert("virus", mailCfg.VirusEmail)
	}
	return err
}

func getMailHeaders(msg []byte, domain string) (*mailHeaders, error) {
	// explicitly initialize headers here (don't return nil) to avoid a
	// panic in deliverMail if parsing fails.
	headers := &mailHeaders{}
	headers.from = ""
	headers.to = nil
	headers.virus = ""

	r := bytes.NewReader(msg)
	m, err := mail.ReadMessage(r)
	if err != nil {
		return headers, fmt.Errorf("failed to parse message: %v", err)
	}

	headers.virus = m.Header.Get("X-SES-Virus-Verdict")

	// FROM
	from, err := mail.ParseAddress(m.Header.Get("From"))
	if err != nil {
		return headers, fmt.Errorf("failed to parse the From address: %v", err)
	}
	headers.from = from.Address

	// TO
	toHeader, err := m.Header.AddressList("To")
	if err == nil {
		// Remove addresses outside our domain
		for _, acct := range toHeader {
			address := strings.ToLower(acct.Address)
			if strings.Contains(address, domain) {
				headers.to = append(headers.to, address)
			}
		}
	}
	if headers.to == nil {
		// Look for the address in the first Received header starting
		// at the top, which should be the header added by SES.
		received := m.Header.Get("Received")
		re := regexp.MustCompile(`(?i)for [<]?(.*@` + domain + `)`)
		to := re.FindStringSubmatch(received)
		if to == nil {
			return headers, fmt.Errorf("failed to parse the recipients: %v", err)
		} else {
			headers.to = append(headers.to, strings.ToLower(to[1]))
		}
	}
	return headers, nil
}

func (mailCfg *mailConfig) sendAlert(category string, body string) {
	if mailCfg.AlertTo == nil || mailCfg.AlertFrom == "" {
		return
	}
	var subject string
	switch category {
	case "virus":
		subject = "fetchses virus alert"
	case "error":
		subject = "fetchses delivery error"
	default:
		// this shouldn't happen
		subject = "fetchses alert"
	}

	msg := []byte("To: " + strings.Join(mailCfg.AlertTo, ",") +
		"\r\nSubject: " + subject + "\r\n\r\n" + body)
	err := smtp.SendMail(mailCfg.SmtpServer, nil, mailCfg.AlertFrom, mailCfg.AlertTo, msg)
	if err != nil {
		log.Printf("failed to send alert: %v", err)
	}
}
