package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net/mail"
	"net/smtp"
	"os"
	"regexp"
	"strings"

	// TODO: https://github.com/aws/aws-sdk-go-v2/issues/1636
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3crypto"
	"gopkg.in/yaml.v3"
)

type logConfig struct {
	Console       bool   `yaml:"console"`
	SyslogNetwork string `yaml:"syslogNetwork"`
	SyslogRaddr   string `yaml:"syslogRaddr"`
}

type s3Config struct {
	Profile       string `yaml:"profile"`
	Bucket        string `yaml:"bucket"`
	NewMailPrefix string `yaml:"newMailPrefix"`
	ErrorPrefix   string `yaml:"errorPrefix"`
	MasterKeyId   string `yaml:"masterKeyId"`
	client        *s3.S3
	decryptClient *s3crypto.DecryptionClientV2
	key           string
}

type mailConfig struct {
	Domain     string   `yaml:"domain"`
	SmtpServer string   `yaml:"smtpServer"`
	ErrorPath  string   `yaml:"errorPath"`
	AlertTo    []string `yaml:"alertTo"`
	AlertFrom  string   `yaml:"alertFrom"`
	VirusEmail string   `yaml:"virusEmail"`
}

type config struct {
	Log  *logConfig  `yaml:"logging"`
	S3   *s3Config   `yaml:"s3"`
	Mail *mailConfig `yaml:"mail"`
}

type mailHeaders struct {
	to    []string
	from  string
	virus string
}

func parseFlags() (string, error) {
	var configPath string
	flag.StringVar(&configPath, "config", "/etc/fetchses.yml", "path to config file")
	flag.Parse()

	fi, err := os.Stat(configPath)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("'%s' is not a normal file", configPath)
	}
	return configPath, nil
}

func getConfigs(cfgPath string) (*logConfig, *s3Config, *mailConfig, error) {
	cfg := &config{}

	file, err := os.Open(cfgPath)
	if err != nil {
		return nil, nil, nil, err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)
	if err := d.Decode(&cfg); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read %s: %v", cfgPath, err)
	}
	// yaml delivers LF, sendmail expects CRLF
	cfg.Mail.VirusEmail = strings.ReplaceAll(cfg.Mail.VirusEmail, "\n", "\r\n")
	return cfg.Log, cfg.S3, cfg.Mail, nil
}

func (s3Cfg *s3Config) connectS3() error {
	sess, err := session.NewSessionWithOptions(session.Options{
		Profile:           s3Cfg.Profile,
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize AWS session: %v", err)
	}
	s3Cfg.client = s3.New(sess)
	s3Cfg.decryptClient, err = initDecryptionClient(sess, s3Cfg.MasterKeyId)
	if err != nil {
		return fmt.Errorf("failed to initialize S3 decryption client: %v", err)
	}
	return nil
}

func initDecryptionClient(sess *session.Session, masterKeyId string) (*s3crypto.DecryptionClientV2, error) {
	cr := s3crypto.NewCryptoRegistry()
	if err := s3crypto.RegisterAESGCMContentCipher(cr); err != nil {
		return nil, err
	}
	// RegisterKMSWrapWithCMK is deprecated, but the current function
	// RegisterKMSContentWrapWithCMK fails with SES-encrypted files.
	// This is likely to change and we'll need to update this.
	if err := s3crypto.RegisterKMSWrapWithCMK(cr, kms.New(sess), masterKeyId); err != nil {
		return nil, err
	}
	svc, err := s3crypto.NewDecryptionClientV2(sess, cr)
	if err != nil {
		return nil, err
	}
	return svc, nil
}

func (s3Cfg *s3Config) listNewMail() ([]string, error) {
	result, err := s3Cfg.client.ListObjectsV2(&s3.ListObjectsV2Input{
		Bucket: aws.String(s3Cfg.Bucket),
		Prefix: aws.String(s3Cfg.NewMailPrefix),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list objects in %s: %v", s3Cfg.Bucket, err)
	}
	var keys []string
	for i := 0; i < int(*result.KeyCount); i++ {
		keys = append(keys, string(*result.Contents[i].Key))
	}
	return keys, nil
}

func (s3Cfg *s3Config) decryptMail() ([]byte, error) {
	var msg []byte
	result, err := s3Cfg.decryptClient.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(s3Cfg.Bucket),
		Key:    aws.String(s3Cfg.key),
	})
	if err == nil {
		msg, err = io.ReadAll(result.Body)
	}
	if err != nil {
		_, filename, _ := strings.Cut(s3Cfg.key, "/")
		err = fmt.Errorf("failed to decrypt S3 object: %v\n"+
			"moving to %s/%s/%s", err, s3Cfg.Bucket,
			s3Cfg.ErrorPrefix, filename)
		if err2 := s3Cfg.moveUndeliveredMail(filename); err2 != nil {
			// Staying with %w for now versus errors.Join() because
			// Unwrap does not work with Join presently.
			err = fmt.Errorf("%w\n%v", err, err2)
		}
	}
	return msg, err
}

func (s3Cfg *s3Config) moveUndeliveredMail(filename string) error {
	_, err := s3Cfg.client.CopyObject(&s3.CopyObjectInput{
		Bucket:     aws.String(s3Cfg.Bucket),
		CopySource: aws.String(s3Cfg.Bucket + "/" + s3Cfg.key),
		Key:        aws.String(s3Cfg.ErrorPrefix + "/" + filename),
	})
	if err != nil {
		return fmt.Errorf("failed to copy S3 object: %v", err)
	}
	return s3Cfg.deleteObject()
}

func (s3Cfg *s3Config) deleteObject() error {
	_, err := s3Cfg.client.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(s3Cfg.Bucket),
		Key:    aws.String(s3Cfg.key),
	})
	if err != nil {
		err = fmt.Errorf("failed to delete S3 object: %v", err)
	}
	return err
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
		return headers, fmt.Errorf("failed to parse From header: %v", err)
	}
	headers.from = from.Address
	// TO
	toHeader, err := m.Header.AddressList("To")
	if err != nil {
		// look for the address in the last Received header
		received := m.Header.Get("Received")
		re := regexp.MustCompile(`for\ (.*@` + domain + `)`)
		to := re.FindStringSubmatch(received)
		if to == nil {
			return headers, fmt.Errorf("failed to parse To address: %v", err)
		} else {
			headers.to = append(headers.to, to[1])
			return headers, nil
		}
	}
	// Remove addresses outside our domain
	for _, acct := range toHeader {
		address := strings.ToLower(acct.Address)
		if strings.Contains(address, domain) {
			headers.to = append(headers.to, address)
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

func fetchSes(s3Cfg *s3Config, mailCfg *mailConfig) int {
	var keys []string
	err := s3Cfg.connectS3()
	if err == nil {
		keys, err = s3Cfg.listNewMail()
	}
	if err != nil {
		log.Println(err)
		mailCfg.sendAlert("error", err.Error())
		return 2
	}

	var exitCode = 0
	var msg []byte
	for _, key := range keys {
		log.Printf("receiving %s/%s", s3Cfg.Bucket, key)
		s3Cfg.key = key
		if msg, err = s3Cfg.decryptMail(); err == nil {
			err = mailCfg.deliverMail(key, msg)
			// A wrapped error means that 1 - SendMail failed and
			// 2 - we failed to write the decrypted data locally.
			// Therefore, do not delete the S3 object.
			if errors.Unwrap(err) == nil {
				err = errors.Join(err, s3Cfg.deleteObject())
			}
		}
		if err != nil {
			// This logs each line separately for syslog
			scanner := bufio.NewScanner(strings.NewReader(err.Error()))
			for scanner.Scan() {
				log.Println(scanner.Text())
			}
			mailCfg.sendAlert("error", err.Error())
			exitCode = 3
		}
	}
	return exitCode
}

func main() {
	log.SetFlags(0)
	cfgPath, err := parseFlags()
	if err != nil {
		log.Fatalln(err)
	}
	logCfg, s3Cfg, mailCfg, err := getConfigs(cfgPath)
	if err != nil {
		log.Fatalln(err)
	}

	var logger *syslog.Writer
	if !logCfg.Console {
		logger, err = syslog.Dial(logCfg.SyslogNetwork, logCfg.SyslogRaddr,
			syslog.LOG_INFO, "fetchses")
		if err != nil {
			log.Fatalln(err)
		}
		log.SetOutput(logger)
	}

	log.Printf("fetchses launched")
	if exitCode := fetchSes(s3Cfg, mailCfg); exitCode != 0 {
		os.Exit(exitCode)
	}
}
