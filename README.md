The use-case is to receive email for my custom domain with AWS's SES service, which encrypts the email and writes it to an S3 bucket.  SES uses client-side encryption and while that is probably a good thing, AWS provides no way to decrypt the messages other than with the AWS SDK for Go, Java, or Ruby.  Hence, this program.

I run fetchses locally to fetch and decrypt the email and send it to a local SMTP server (that passes it on to a local IMAP server).  Since it pulls from S3, I don't need a static IP address or open inbound ports for the SMTP server.  The server can be completely private.  It is written with this use-case in mind.  Once emails are fetched and decrypted, the program trusts the local environment.  Be mindful of that if you use it.

The larger point of this is that I can run my own private email server and let AWS deal with DKIM, SPF, DMarc, IP reputation, spam/virus scanning, and the security challenges of running a publicly-exposed SMTP server.

I added comments to fetchses.yml.example that should be sufficient for using the program.  You need a properly configured SMTP server to go with it.  The program takes up to three command-line arguments:
- the path to the config file (it defaults to ~/.config/fetchses.yml).
- the S3 bucket storing the incoming email.  This can also be set in the config file.  The argument overrides the config file.
- an S3 file name (including prefix) for a specific email.  If this is not set, the program will list/read all emails in the configured bucket and prefix.

I added the bucket and key arguments to go with SNS notifications for new mail.  The SNS notifications contain the bucket and key for new mail, so I use that to fetch those specific files in near-real-time as the mail arrives.  It is still useful to list and read all files if something goes wrong.  You can run it manually then and fetch whatever is there.

As a rule, I left out anything that I can otherwise do with the SMTP and IMAP servers, like aliases, sieve rules, and spam/virus scanning.  That said, I have chosen (for now) to use SES's spam and virus scanning.  SES adds headers indicating PASS or FAIL for each.  fetchses checks the SES virus header and sends an alert email to me if the header is FAIL.  I also have postfix check for that header and quarantine the email.  However postfix will not notify me of it.  So fetchses notifies me.  I use a sieve rule to deal with the SES spam header.

I don't anticipate doing much more with fetchses.  I'll address bugs and CVEs of course and otherwise stay in step with updates to the AWS SDK for Go, SES, and S3.   I hope this is infrequent.
