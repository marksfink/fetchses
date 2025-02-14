package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
	"os/exec"
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
	S3   *s3Session  `yaml:"s3"`
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

func getConfigs(cfgPath string) (*logConfig, *s3Session, *mailConfig, error) {
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
	cfg.Mail.Domain = strings.ToLower(cfg.Mail.Domain)
	return cfg.Log, cfg.S3, cfg.Mail, nil
}

func logError(err error) {
	// This logs each line separately for syslog
	scanner := bufio.NewScanner(strings.NewReader(err.Error()))
	for scanner.Scan() {
		log.Println(scanner.Text())
	}
}

func alert(script string, alerterr error) error {
	cmd := exec.Command(script)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Printf("the alert script failed:\n%v", err)
		return err
	}
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, alerterr.Error())
	}()
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("the alert script failed:\n%s\n%v", output, err)
	}
	return err
}

func fetchSes(sess *s3Session, mailCfg *mailConfig) error {
	var keys []string
	err := sess.connectS3()
	if err == nil {
		if sess.key == "" {
			keys, err = sess.listNewMail()
		} else {
			keys = []string{sess.key}
		}
	}
	if err != nil {
		logError(err)
		if mailCfg.AlertScript != "" {
			err = errors.Join(err, alert(mailCfg.AlertScript, err))
		}
		return err
	}

	var msg []byte
	var loopErr error
	for _, key := range keys {
		log.Printf("receiving %s/%s", sess.Bucket, key)
		sess.key = key
		msg, err = sess.decryptMail()
		if err == nil {
			err = mailCfg.deliverMail(key, msg)
		}
		// A wrapped error here means that 1 - SendMail failed and
		// 2 - we failed to write the decrypted data locally.
		// In that case, do not delete the S3 object.
		if errors.Unwrap(err) == nil {
			err = errors.Join(err, sess.deleteObject())
		}
		if err != nil {
			logError(err)
			if mailCfg.AlertScript != "" {
				err = errors.Join(err, alert(mailCfg.AlertScript, err))
			}
			loopErr = err
		}
	}
	return loopErr
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

	s3Cfg.ctx = context.Background()

	if args.bucket != "" {
		s3Cfg.Bucket = args.bucket
	}
	if args.key != "" {
		s3Cfg.key = args.key
	} else {
		log.Printf("reading all new mail in the bucket")
	}
	// TODO: validate config values

	err = fetchSes(s3Cfg, mailCfg)
	if err != nil {
		os.Exit(1)
	}
}
