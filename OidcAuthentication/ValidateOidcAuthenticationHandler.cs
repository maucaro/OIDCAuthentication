using System;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OidcAuthentication {
  public class ValidateOidcAuthenticationHandler : AuthenticationHandler<ValidateOidcAuthenticationSchemeOptions> {
    public ValidateOidcAuthenticationHandler(
        IOptionsMonitor<ValidateOidcAuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock)
        : base(options, logger, encoder, clock) { }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
      if (!Request.Headers.ContainsKey("Authorization")) {
        return AuthenticateResult.Fail("Authorization header missing");
      }
      var rawToken = ExtractRawToken(Request.Headers["Authorization"].ToString());
      if (string.IsNullOrWhiteSpace(rawToken)) {
        return AuthenticateResult.Fail("Bearer token missing");
      }
      try {
        // Payload returned by JsonWebSignature.VerifySignedTokenAsync does not include the email claim.
        // Bug filed: https://github.com/googleapis/google-api-dotnet-client/issues/1878
        // In the meantime, will decode and deserialize it manually.
        // JsonWebSignature.Payload payload = await JsonWebSignature.VerifySignedTokenAsync(token, Options.TokenVerificationOptions);
        var generalValidationTask = JsonWebSignature.VerifySignedTokenAsync(rawToken, Options.TokenVerificationOptions);
        var payload = rawToken.Split('.').ElementAtOrDefault(1);    // A token has the form 'header.payload.signature'
        TokenClaims tokenClaims = JsonSerializer.Deserialize<TokenClaims>(Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(payload)));
        if (string.IsNullOrWhiteSpace(tokenClaims.Sub) || string.IsNullOrWhiteSpace(tokenClaims.Email)) {
          return AuthenticateResult.Fail("Error validating token: 'sub' and 'email' claims are required");
        }
        var claims = new[] {
                    new Claim(ClaimTypes.NameIdentifier, tokenClaims.Sub),
                    new Claim(ClaimTypes.Email, tokenClaims.Email)};
        var claimsIdentity = new ClaimsIdentity(claims, nameof(ValidateOidcAuthenticationHandler));
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(claimsIdentity), this.Scheme.Name);
        await generalValidationTask.ConfigureAwait(false);
        return AuthenticateResult.Success(ticket);
      } catch (Exception ex) {
        return ex switch {
          // Payload decoding failed - malformed input (i.e. whitespace or padding characters)
          FormatException or ArgumentNullException => AuthenticateResult.Fail("Error validating token: payload decoding failed"),
          // Payload failed to serialize to JSON
          JsonException => AuthenticateResult.Fail("Error validating token: converting payload to JSON failed"),
          // Token failed verification
          _ => AuthenticateResult.Fail($"Error validating token: ${ex.Message}"),
        };
      }
    }

    private static string ExtractRawToken(string Header) {
      if (string.IsNullOrWhiteSpace(Header)) {
        return string.Empty;
      }
      string[] splitHeader = Header.ToString().Split(' ');
      if (splitHeader.Length != 2) {
        return string.Empty;
      }
      var scheme = splitHeader[0];
      var token = splitHeader[1];
      if (string.IsNullOrWhiteSpace(token) || scheme.ToLowerInvariant() != "bearer") {
        return string.Empty;
      }
      return token;
    }

    private class TokenClaims {
      [JsonPropertyName("sub")]
      public string Sub { get; set; }

      [JsonPropertyName("email")]
      public string Email { get; set; }
    }
  }
}
