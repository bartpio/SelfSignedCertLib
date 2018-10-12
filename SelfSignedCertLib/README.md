Self Signed certificate generation library, wrapping BouncyCastle, making it easy to generate an untrusted CA (Certificate Authority) on the fly, and certificates using that CA on the fly. Such CAs and certificates are primarily for development purposes. Bouncy types aren't directly exposed; we expose as public only standard net framework types (ex. X509Certificate2).

Net Standard version coming soon.

NuGet package:
https://www.nuget.org/packages/SelfSignedCertLib

Many thanks to the contributors on this stackoverflow post:
https://stackoverflow.com/a/22237794