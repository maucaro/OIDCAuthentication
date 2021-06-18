using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication;

namespace OidcAuthentication {
  public class ValidateOidcAuthenticationSchemeOptions : AuthenticationSchemeOptions {
    public SignedTokenVerificationOptions TokenVerificationOptions { get; set; }
  }
}
