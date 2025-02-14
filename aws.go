package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	crypto "github.com/aws/amazon-s3-encryption-client-go/v3/client"
	"github.com/aws/amazon-s3-encryption-client-go/v3/materials"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type s3Session struct {
	Profile       string `yaml:"profile"`
	Bucket        string `yaml:"bucket"`
	NewMailPrefix string `yaml:"newMailPrefix"`
	ErrorPrefix   string `yaml:"errorPrefix"`
	KmsKeyId      string `yaml:"kmsKeyId"`
	ctx           context.Context
	client        *s3.Client
	decrypt       *crypto.S3EncryptionClientV3
	key           string
}

func (sess *s3Session) connectS3() error {
	cfg, err := awsconfig.LoadDefaultConfig(sess.ctx,
		awsconfig.WithSharedConfigProfile(sess.Profile))
	if err != nil {
		return fmt.Errorf("failed to load AWS config, %v", err)
	}
	sess.client = s3.NewFromConfig(cfg)
	// EnableLegacyWrappingAlgorithms is required with S3 objects that SES writes.
	cmm, err := materials.NewCryptographicMaterialsManager(
		materials.NewKmsKeyring(kms.NewFromConfig(cfg), sess.KmsKeyId,
			func(options *materials.KeyringOptions) {
				options.EnableLegacyWrappingAlgorithms = true
			},
		),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize cmm, %v", err)
	}
	sess.decrypt, err = crypto.New(sess.client, cmm)
	if err != nil {
		return fmt.Errorf("failed to initialize encryption client, %v", err)
	}
	return nil
}

func (sess *s3Session) listNewMail() ([]string, error) {
	result, err := sess.client.ListObjectsV2(sess.ctx,
		&s3.ListObjectsV2Input{
			Bucket: aws.String(sess.Bucket),
			Prefix: aws.String(sess.NewMailPrefix),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list objects in %s: %v", sess.Bucket, err)
	}
	var keys []string
	for i := 0; i < int(*result.KeyCount); i++ {
		keys = append(keys, string(*result.Contents[i].Key))
	}
	return keys, nil
}

func (sess *s3Session) decryptMail() ([]byte, error) {
	var msg []byte

	// In 1/2025, AWS started validating checksums by default when getting
	// S3 objects. SES does not include checksums when it writes to S3, so we
	// get a warning about it when getting the object. The option below
	// disables the check so we don't get the warning.
	result, err := sess.decrypt.GetObject(sess.ctx,
		&s3.GetObjectInput{
			Bucket: aws.String(sess.Bucket),
			Key:    aws.String(sess.key),
		},
		func(options *s3.Options) {
			options.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		},
	)
	if err == nil {
		msg, err = io.ReadAll(result.Body)
	}
	if err != nil {
		_, filename, _ := strings.Cut(sess.key, "/")
		err = fmt.Errorf("failed to decrypt S3 object: %v\n"+
			"moving to %s/%s/%s", err, sess.Bucket, sess.ErrorPrefix, filename)
		if err2 := sess.moveUndeliveredMail(filename); err2 != nil {
			err = fmt.Errorf("%w\n%v", err, err2)
		}
	}
	return msg, err
}

func (sess *s3Session) moveUndeliveredMail(filename string) error {
	_, err := sess.client.CopyObject(sess.ctx,
		&s3.CopyObjectInput{
			Bucket:     aws.String(sess.Bucket),
			CopySource: aws.String(sess.Bucket + "/" + sess.key),
			Key:        aws.String(sess.ErrorPrefix + "/" + filename),
		},
	)
	if err != nil {
		return fmt.Errorf("failed to copy S3 object: %v", err)
	}
	return sess.deleteObject()
}

func (sess *s3Session) deleteObject() error {
	_, err := sess.client.DeleteObject(sess.ctx,
		&s3.DeleteObjectInput{
			Bucket: aws.String(sess.Bucket),
			Key:    aws.String(sess.key),
		},
	)
	if err != nil {
		err = fmt.Errorf("failed to delete S3 object: %v", err)
	}
	return err
}
