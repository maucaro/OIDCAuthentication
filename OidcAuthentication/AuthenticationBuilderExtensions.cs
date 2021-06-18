using System;
using Microsoft.AspNetCore.Authentication;

namespace OidcAuthentication {
  public static class AuthenticationBuilderExtensions {
    public static AuthenticationBuilder AddCustomAuth(this AuthenticationBuilder builder, Action<ValidateOidcAuthenticationSchemeOptions> configureOptions) {
      return builder.AddScheme<ValidateOidcAuthenticationSchemeOptions, ValidateOidcAuthenticationHandler>
          (OidcAuthenticationDefaults.AuthenticationScheme, configureOptions);
    }
  }
}
