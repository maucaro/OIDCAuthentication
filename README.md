# OidcAuthentication

This solution implements an ASP.NET (Core) custom Authentication Handler and Scheme for OIDC tokens (user_id) passed in the Authorization HTTP header (Bearer Token; see: (https://datatracker.ietf.org/doc/html/rfc6750)) The CertificatesUrl setting in appsetting.json is for Google Identity Platform/Firebase. It also includes a sample Web Api that uses the filter and a Unit Testing project.

Special thanks to these very helpful posts:

- (https://ignas.me/tech/custom-authentication-asp-net-core-20/)
- (https://referbruv.com/blog/posts/implementing-custom-authentication-scheme-and-handler-in-aspnet-core-3x)

This answer in SO was key in setting up unit testing: https://stackoverflow.com/questions/58963133/unit-test-custom-authenticationhandler-middleware

Enjoy
