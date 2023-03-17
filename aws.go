package main

import (
	"fmt"
	"io"
	"strings"

	// TODO: https://github.com/aws/aws-sdk-go-v2/issues/1636
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3crypto"
)

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
