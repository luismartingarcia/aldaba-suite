# aldaba-suite
An open source Single Packet Authorization and Port Knocking authentication system for GNU/Linux.

http://www.aldabaknocking.com

Nowadays system administrators cannot rely on the security provided by software manufacturers to protect services that run on their network servers. 0-day exploits are serious threats for critical systems that can't afford security breaches. Port Knocking and Single Packet Authorization are two different techniques that provide a mechanism to have all ports of a server closed and open them on request, to clients that have the appropriate authentication credentials. Aldaba is a command-line tool for Linux systems that implements a complete PK and SPA authentication service that is both effective and easy to use.

Current Features

- Support for two authentication protocols: Port Knocking and Single Packet Authorization.
- Fast authentication processing.
- IPv6 capable.
- Not vulnerable to replay attacks.
- Encryption using any of: AES/Rijndael, Twofish, Blowfish and Serpent.
- Authentication through HMAC-SHA256.
- PBKDF2-based key derivation.
- Support for custom command execution upon successful client authentication.
- Sensitive data wiping on exit.
- Support for decoys and noise packets.
- Logging capabilities.
- External IP address resolution.
- Highly commented source code.
- Doxygen based documentation.
- Free and Open Source.
