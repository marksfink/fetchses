package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"os/user"
	"path/filepath"
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

type flags struct {
	configPath string
	bucket     string
	key        string
}

var (
	version = "dev"
	date    = "unknown"
	commit  = "none"
)

func parseFlags() (*flags, error) {
	args := &flags{}
	flag.StringVar(&args.configPath, "config", "", "Path to the config file (default ~/.config/fetchses.yml)")
	flag.StringVar(&args.bucket, "bucket", "", "S3 bucket containing incoming email "+
		"(this overrides the config file)")
	flag.StringVar(&args.key, "key", "", "Specific email file to fetch "+
		"(if not set, we read all files in the configured bucket and prefix)")
	flag.Parse()

	if args.configPath == "" {
		user, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("could not determine the current user to find the config file")
		}
		args.configPath = user.HomeDir + "/.config/fetchses.yml"
	}
	fi, err := os.Stat(args.configPath)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("'%s' is not a normal file", args.configPath)
	}
	return args, nil
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
		if s3Cfg.key == "" {
			keys, err = s3Cfg.listNewMail()
		} else {
			keys = []string{s3Cfg.key}
		}
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

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s %s %s %s:\n", os.Args[0], version, date, commit)
		flag.PrintDefaults()
	}
	args, err := parseFlags()
	if err != nil {
		log.Fatalln(err)
	}
	logCfg, s3Cfg, mailCfg, err := getConfigs(args.configPath)
	if err != nil {
		log.Fatalln(err)
	}

	bin := filepath.Base(os.Args[0])
	var logger *syslog.Writer
	if !logCfg.Console {
		logger, err = syslog.Dial(logCfg.SyslogNetwork, logCfg.SyslogRaddr,
			syslog.LOG_INFO, bin)
		if err != nil {
			log.Fatalln(err)
		}
		log.SetOutput(logger)
	}

	log.Printf("%s launched", bin)
	if args.bucket != "" {
		s3Cfg.Bucket = args.bucket
	}
	if args.key != "" {
		s3Cfg.key = args.key
	} else {
		log.Printf("reading all new mail in the bucket")
	}
	// TODO: validate config values

	if exitCode := fetchSes(s3Cfg, mailCfg); exitCode != 0 {
		os.Exit(exitCode)
	}
}
