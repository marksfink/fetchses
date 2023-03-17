package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type logConfig struct {
	Console       bool   `yaml:"console"`
	SyslogNetwork string `yaml:"syslogNetwork"`
	SyslogRaddr   string `yaml:"syslogRaddr"`
}

type config struct {
	Log  *logConfig  `yaml:"logging"`
	S3   *s3Config   `yaml:"s3"`
	Mail *mailConfig `yaml:"mail"`
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
	// yaml delivers LF, smtp.SendMail expects CRLF
	cfg.Mail.VirusEmail = strings.ReplaceAll(cfg.Mail.VirusEmail, "\n", "\r\n")
	cfg.Mail.Domain = strings.ToLower(cfg.Mail.Domain)
	return cfg.Log, cfg.S3, cfg.Mail, nil
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
