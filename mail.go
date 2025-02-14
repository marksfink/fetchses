package main

import (
	"bytes"
	"fmt"
	"net/mail"
	"net/smtp"
	"os"
	"regexp"
	"strings"
)

type mailConfig struct {
	Domain      string `yaml:"domain"`
	SmtpServer  string `yaml:"smtpServer"`
	ErrorPath   string `yaml:"errorPath"`
	AlertScript string `yaml:"alertScript"`
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
		_, filename, _ := strings.Cut(key, "/")
		err = fmt.Errorf("failed to deliver message: %v\n"+
			"writing decrypted data to %s/%s", err, mailCfg.ErrorPath, filename)
		if err2 := writeFile(mailCfg.ErrorPath, filename, msg); err2 != nil {
			err = fmt.Errorf("%w\n%v", err, err2)
		}
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
	if headers.virus == "FAIL" {
		err = fmt.Errorf("email failed virus scan")
		return headers, err
	}

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

func writeFile(path string, file string, msg []byte) error {
	err := os.MkdirAll(path, 0750)
	if err == nil {
		var f *os.File
		f, err = os.OpenFile(path+"/"+file, os.O_CREATE|os.O_WRONLY, 0640)
		if err == nil {
			defer f.Close()
			_, err = fmt.Fprintf(f, "%s\n", msg)
		}
	}
	return err
}
