# Canary-Token-Automation-using-Golang

This Go program is designed to automate the canary token process, providing a way to generate and validate canary tokens for security monitoring.

The program uses Go's `crypto/rand` package to generate a random token, the `crypto/sha256` package to hash the token with a secret key, and the `encoding/base64` package to encode the token. When a token is received, it's then decoded from base64 and re-hashed using the same secret key, the received token is then compared to the re-hashed token to check the validity of the token. The program also provides the functionality of expiry time of the token, which can be set by modifying the `expiry` constant variable.

The program provides a basic implementation of the canary token process, but it can be further enhanced to include additional security measures such as token expiry, token revocation, and integration with monitoring and alerting systems.

Please note that, this is a example and it might not work as is as it is not tested. Also, this program uses a hardcoded key for demonstration purposes, it is recommended to use a more secure key management solution in a production environment.

Canary tokens are often used as a form of security measure, allowing organizations to detect unauthorized access to sensitive information. By generating unique tokens and embedding them in various locations, organizations can monitor for their use and quickly identify potential breaches. In the above program, the canary token is generated by creating a random token, adding a secret key to it, and encoding it in base64. This generated token can then be placed in various locations, such as files or network packets. If the token is detected in an unexpected location, it can indicate a potential security breach.

This program provides a basic implementation of the canary token process, but it can be further enhanced to include additional security measures such as token expiry, token revocation, and integration with monitoring and alerting systems. It is also important to note that the security of the canary token process depends on the secrecy of the secret key used to generate and validate tokens, so it is important to use a secure key management solution in a production environment.

## Prerequisites
- Golang should be installed on the machine on which you are running the program.
- The user running the program should have permission to run the program.

## Configuration
- You can modify the `secret` constant variable to any value you want to use as a secret key.
- You can modify the `expiry` constant variable to set the expiry time for the tokens.

## Output
- The program will output the new canary token when it is generated.
- The program will output whether the token is valid or not when it is checked.

# Warning
- This program uses a hardcoded key for demonstration purposes, it is recommended to use a more secure key management solution in a production environment.
- This is just an example and it might not work as is.
- Make sure you understand the impact of this program before running it.

## How To Run
Run the program using the command `go run <filename.go>`
The program will start running, generating new canary token and validating it.

## Next Steps
- Add functionality of token expiry, token revocation and integration with monitoring and alerting systems.
- Use a secure key management solution in a production environment.
- **Test the program in a lab environment before running it in production.**
