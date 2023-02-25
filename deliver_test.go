package main

import (
	"io"
	"log"
	"os"
	"strings"
	"testing"
)

func TestVirusSuccess(t *testing.T) {
	// postfix should hold the email and we should receive an alert email
	log.SetFlags(0)
	file, err := os.Open("virus.eml")
	if err != nil {
		log.Fatalln(err)
	}
	msg, err := io.ReadAll(file)
	if err != nil {
		log.Fatalln(err)
	}
	cfgPath, err := parseFlags()
	if err != nil {
		log.Fatalln(err)
	}
	_, _, cfg, err := getConfigs(cfgPath)
	if err != nil {
		log.Fatalln(err)
	}
	err = cfg.deliverMail("incoming/virus.eml", msg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVirusFail(t *testing.T) {
	// sendmail should fail, logs should indicate virus
	// email should be written to undelivered directory
	log.SetFlags(0)
	file, err := os.Open("virus-fail.eml")
	if err != nil {
		log.Fatalln(err)
	}
	msg, err := io.ReadAll(file)
	if err != nil {
		log.Fatalln(err)
	}
	cfgPath, err := parseFlags()
	if err != nil {
		log.Fatalln(err)
	}
	_, _, cfg, err := getConfigs(cfgPath)
	if err != nil {
		log.Fatalln(err)
	}
	err = cfg.deliverMail("incoming/virus-fail.eml", msg)
	if err == nil || !strings.Contains(err.Error(), "THIS EMAIL FAILED SES VIRUS SCAN") {
		t.Fatal(err)
	} else {
		log.Println(err)
	}
}

func TestEmailMultipleRecipients(t *testing.T) {
	// multiple local domain recipients should receive the email
	// yahoo.com recipient should not be sent.
	// all recipients should appear in email
	log.SetFlags(0)
	file, err := os.Open("recipients.eml")
	if err != nil {
		log.Fatalln(err)
	}
	msg, err := io.ReadAll(file)
	if err != nil {
		log.Fatalln(err)
	}
	cfgPath, err := parseFlags()
	if err != nil {
		log.Fatalln(err)
	}
	_, _, cfg, err := getConfigs(cfgPath)
	if err != nil {
		log.Fatalln(err)
	}
	err = cfg.deliverMail("incoming/recipients.eml", msg)
	if err != nil {
		t.Fatal(err)
	}
}
