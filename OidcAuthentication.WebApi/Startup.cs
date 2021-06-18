using Google.Apis.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;

namespace OidcAuthentication.WebApi {
  public class Startup {
    public Startup(IConfiguration configuration) {
      Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    // This method gets called by the runtime. Use this method to add services to the container.
    public void ConfigureServices(IServiceCollection services) {
      services.AddAuthentication(options => {
        options.DefaultAuthenticateScheme = OidcAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OidcAuthenticationDefaults.AuthenticationScheme;
      })
      .AddCustomAuth(options => {
        SignedTokenVerificationOptions tokenOptions = new();
        Configuration.GetSection("OidcOptions").Bind(tokenOptions);
        options.TokenVerificationOptions = tokenOptions;
      });

      services.AddControllers();
      services.AddSwaggerGen(c => {
        c.SwaggerDoc("v1", new OpenApiInfo { Title = "WebApiCustomAuthOidc", Version = "v1" });
      });


    }

    // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
      if (env.IsDevelopment()) {
        app.UseDeveloperExceptionPage();
        app.UseSwagger();
        app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "WebApiCustomAuthOidc v1"));
      }

      app.UseHttpsRedirection();

      app.UseRouting();

      app.UseAuthentication();

      app.UseAuthorization();

      app.UseEndpoints(endpoints => {
        endpoints.MapControllers();
      });
    }
  }
}
