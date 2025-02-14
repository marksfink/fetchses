The use-case for this is to receive email for my personal domain with AWS's SES service, which encrypts the email and writes it to an S3 bucket.  SES uses client-side encryption and while that is probably a good thing, AWS provides no way to decrypt the messages other than with the SDK for Go, Java, or Ruby.  Hence, this program.

I run fetchses locally to fetch and decrypt the email and send it to a local SMTP server.  Thus, the SMTP and IMAP servers can be private while we let AWS deal with the security challenges of running a publicly-exposed SMTP server.

I added comments to fetchses.yml.example that should be sufficient for using the program.  The program takes up to three command-line arguments:
- the path to the config file (it defaults to ~/.config/fetchses.yml).
- the S3 bucket storing the incoming email.  This can also be set in the config file.  The argument overrides the config file.
- an S3 file name (including prefix) for a specific email.  If this is not set, the program will retrieve all emails in the configured bucket and prefix.

I added the bucket and key arguments to go with SNS notifications for new mail.  The SNS notifications contain the bucket and key for new mail, so I use that to fetch those specific files when they arrive.  It is still useful to retrieve all files if something goes wrong with the SNS notifications.

As a rule, I left out anything that I can otherwise do with the SMTP and IMAP servers, like aliases, sieve rules, and spam/virus scanning.  That said, I have chosen for now to use SES's spam and virus scanning.  SES adds headers indicating PASS or FAIL for each.  fetchses checks the SES virus header and if it is FAIL, it will quarantine the email and send an alert.  Granted, postfix can also check for that header and quarantine the email; however postfix will not notify me of it, thus I baked it into fetchses.  Otherwise, I use a sieve rule to deal with the SES spam header.

For alerting on viruses and errors, the latest version triggers a script (or any binary) that you specify in the config, and sends the error message to it via stdin.  You can then write the script to alert however you want.  I decided this is better than coding any specific alert mechanism into fetchses.
