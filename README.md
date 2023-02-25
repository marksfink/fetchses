The use-case is to receive email for my custom domain with AWS's SES service, which encrypts the email (with a KMS key as defined in an SES Receipt Rule), and writes the email to an S3 bucket.  SES uses client-side encryption and while that is probably a good thing, they provide no way to decrypt the messages without coding.  Hence, fetchses.

I run fetchses locally to fetch and decrypt the email and send it to a local, private SMTP server that passes it on to a local, private IMAP server.  Since it pulls from S3, I don't need a static IP address or open inbound ports.  The server can be completely private.  It is written with this use-case in mind and no others.  Once emails are fetched and decrypted, the program trusts the local environment.  Be mindful of that if you use it.

The larger point of this is that I can run my own private email server and let AWS deal with DKIM, SPF, DMarc, IP reputation, spam/virus scanning, and the security challenges of running a publicly-exposed SMTP server. 

I added comments to fetchses.yml.example that should be sufficient for using the program.  You obviously need a properly configured SMTP server to go with it, and probably an IMAP server also.  The program takes one command-line argument which is the path to the config file (default is /etc/fetchses.yml), although you could change this before you build it.

As a rule, I left out anything that I can otherwise do with the SMTP and IMAP servers, like aliases, sieve rules, and spam/virus scanning.  That said, I have chosen (for now) to use SES's spam and virus scanning.  SES adds headers indicating PASS or FAIL for each.  fetchses checks the virus header and sends an alert email to me if the header is FAIL.  I also have postfix check for that header and quarantine the email.  However postfix will not notify me of it.  So I added the check in fetchses to notify me.  I use sieve rules to check and deal with the SES spam header.  Checking that header would be easy to add to fetchses, I just can't think of a reason to.

I don't anticipate doing much more with fetchses (beyond bug fixes) because it is relatively simple after all.  The only reason to update it will be to stay in step with changes to the AWS SDK for Go, SES, S3, and CVEs that may arise.   I hope this is infrequent.

Also, I'm just starting to run this server in this way, so we'll see in a few months or a year if I still think it's a good idea!
