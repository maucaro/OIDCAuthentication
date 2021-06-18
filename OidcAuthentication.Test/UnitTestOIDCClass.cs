using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace OidcAuthentication.Test {
  [TestClass]
  public class UnitTestOidcClass {
    private readonly Mock<IOptionsMonitor<ValidateOidcAuthenticationSchemeOptions>> _options;
    private readonly Mock<ILoggerFactory> _loggerFactory;
    private readonly Mock<UrlEncoder> _encoder;
    private readonly Mock<ISystemClock> _clock;
    private readonly ValidateOidcAuthenticationHandler _handler;
    private readonly string User;
    private readonly string Password;
    private readonly string AuthUrl;

    public UnitTestOidcClass() {
      const string environmentName = "Development";
      var configuration = new ConfigurationBuilder()
          .SetBasePath(Directory.GetCurrentDirectory())
          .AddJsonFile("appsettings.json")
          .AddJsonFile($"appsettings.{environmentName}.json", true, true)
          .Build();
      SignedTokenVerificationOptions tokenOptions = new();
      configuration.GetSection("OidcOptions").Bind(tokenOptions);
      tokenOptions.IssuedAtClockTolerance = TimeSpan.FromMinutes(1);
      ValidateOidcAuthenticationSchemeOptions options = new();
      options.TokenVerificationOptions = tokenOptions;
      User = configuration.GetValue<string>("user");
      Password = configuration.GetValue<string>("password");
      AuthUrl = configuration.GetValue<string>("authUrl");
      _options = new Mock<IOptionsMonitor<ValidateOidcAuthenticationSchemeOptions>>();

      // This Setup is required for .NET Core 3.1 onwards.
      _options
          .Setup(x => x.Get(It.IsAny<string>()))
          .Returns(options);

      var logger = new Mock<ILogger<ValidateOidcAuthenticationHandler>>();
      _loggerFactory = new Mock<ILoggerFactory>();
      _loggerFactory.Setup(x => x.CreateLogger(It.IsAny<String>())).Returns(logger.Object);

      _encoder = new Mock<UrlEncoder>();
      _clock = new Mock<ISystemClock>();

      _handler = new ValidateOidcAuthenticationHandler(_options.Object, _loggerFactory.Object, _encoder.Object, _clock.Object);
    }

    private async Task TestMiddleware_Fail(string header, string expectedMessage) {
      var context = new DefaultHttpContext();
      if (!string.IsNullOrWhiteSpace(header)) {
        context.Request.Headers.Add("authorization", header);
      }

      await _handler.InitializeAsync(new AuthenticationScheme(OidcAuthenticationDefaults.AuthenticationScheme, null, typeof(ValidateOidcAuthenticationHandler)), context);
      var result = await _handler.AuthenticateAsync();
      Assert.IsFalse(result.Succeeded);
      Assert.AreEqual(expectedMessage, result.Failure.Message);
    }

    [TestMethod]
    public async Task Test_NoAuthorizationHeader() {
      await TestMiddleware_Fail(string.Empty, "Authorization header missing");
    }

    [TestMethod]
    public async Task Test_SchemeNotBearer() {
      await TestMiddleware_Fail("basic xyz", "Bearer token missing");
    }

    [TestMethod]
    public async Task Test_TokenWithNoPayload() {
      await TestMiddleware_Fail("bearer xyz", "Error validating token: payload decoding failed");
    }

    [TestMethod]
    public async Task Test_TokenPayloadNotDecodable() {
      await TestMiddleware_Fail("bearer x.y.z", "Error validating token: payload decoding failed");
    }

    [TestMethod]
    public async Task Test_TokenNoEmail() {
      // Token generated at jwt.io with no email claim
      await TestMiddleware_Fail("bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "Error validating token: 'sub' and 'email' claims are required");
    }

    [TestMethod]
    public async Task Test_TokenInvalidSignature() {
      // Token generated at jwt.io with email claim; will fail on signature verification
      await TestMiddleware_Fail("bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZW1haWwiOiJtYXVAbWF1Y2Fyby5jb20iLCJpYXQiOjE1MTYyMzkwMjJ9.W40zbjC93MwX2F1q5f-Cw8Hnz0YTCPvu0lqQgCJicPk", "Error validating token: $Signing algorithm must be either RS256 or ES256.");
    }

    [TestMethod]
    public async Task Test_TokenExpired() {
      // Valid but expired token
      await TestMiddleware_Fail("bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImRjNGQwMGJjM2NiZWE4YjU0NTMzMWQxZjFjOTZmZDRlNjdjNTFlODkiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vdXRpbGl0eS1kZXNjZW50LTE4NTExOSIsImF1ZCI6InV0aWxpdHktZGVzY2VudC0xODUxMTkiLCJhdXRoX3RpbWUiOjE2MjM3ODI5NzUsInVzZXJfaWQiOiJkRWFIcmdyUmxoY0Q4QlpXdElqN2xiNU5PbGsyIiwic3ViIjoiZEVhSHJnclJsaGNEOEJaV3RJajdsYjVOT2xrMiIsImlhdCI6MTYyMzc4Mjk3NSwiZXhwIjoxNjIzNzg2NTc1LCJlbWFpbCI6Im1hdUBtYXVjYXJvLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZmlyZWJhc2UiOnsiaWRlbnRpdGllcyI6eyJlbWFpbCI6WyJtYXVAbWF1Y2Fyby5jb20iXX0sInNpZ25faW5fcHJvdmlkZXIiOiJwYXNzd29yZCJ9fQ.QMh9qWud9IIn6KQjM5pbA9vFpF0PddVB3klVgmbKaJyaKKqyDbTFw7p41ePhgL0zqeYhVL9opdo4BXt5U17-SmfOPIaPvka_Gn0dFa2eZVbOpEYuuoNd4_R8Stw6uaiBomp607I3ydndd6LIG-oRXcJfgtcxwgR_VpASjsZl1ydYe-nq1ly3NoOLb3Hp_UWCehH9-Yu0JkaGqP0lnZt8qj3aI-coBddCm_eRtC9WtaHOKyIA5qJgHK8NJ4qO7NF80GOiZHYwE1iQMETOMqyaMlR425vjXsCcLLGsLQR196yYYY9Y8YHo5bbe_dW7UVcieOw3jCCQ0IM7ZkvIHtQNtw", "Error validating token: $JWT has expired.");
    }

    [TestMethod]
    public async Task Test_Authenticated() {
      Uri uri = new(AuthUrl);
      string data = "{\"email\":\"" + User + "\",\"password\":\"" + Password + "\",\"returnSecureToken\":true}";

      WebClient client = new();
      client.Headers.Add("Content-Type", "application/json");
      var res = client.UploadString(uri, data);
      JsonDocument payloadJson = JsonDocument.Parse(res);
      var token = payloadJson.RootElement.TryGetProperty("idToken", out JsonElement element) ? element.GetString() : string.Empty;

      var context = new DefaultHttpContext();
      context.Request.Headers.Add("authorization", "bearer " + token);

      await _handler.InitializeAsync(new AuthenticationScheme(OidcAuthenticationDefaults.AuthenticationScheme, null, typeof(ValidateOidcAuthenticationHandler)), context);
      var result = await _handler.AuthenticateAsync();

      Assert.IsTrue(result.Succeeded);
      Assert.AreEqual(result.Principal.Claims.First(v => v.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress").Value, User);
    }
  }
}
