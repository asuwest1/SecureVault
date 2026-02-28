using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using SecureVault.Api.Middleware;
using SecureVault.Api.Services;
using SecureVault.Core.Interfaces;
using SecureVault.Infrastructure.Data;
using SecureVault.Infrastructure.Services;

var builder = WebApplication.CreateBuilder(args);

// ─────────────────────────────────────────────────────────────────────────────
// Serilog — configured first; includes log-scrubbing for sensitive fields
// ─────────────────────────────────────────────────────────────────────────────
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .Destructure.ByTransforming<object>(obj => ScrubSensitiveFields(obj))
    .WriteTo.Console()
    .CreateLogger();

builder.Host.UseSerilog();

// ─────────────────────────────────────────────────────────────────────────────
// Database — PostgreSQL via Npgsql EF Core
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Default"))
           .UseSnakeCaseNamingConvention());

builder.Services.AddDbContextFactory<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Default"))
           .UseSnakeCaseNamingConvention());

// ─────────────────────────────────────────────────────────────────────────────
// Services — Core & Infrastructure
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddSingleton<IEncryptionService, EncryptionService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<IPermissionService, PermissionService>();
builder.Services.AddSingleton<SyslogForwarder>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<MfaService>();
builder.Services.AddScoped<FirstRunService>();

// Conditional LDAP service — only when Auth:Mode = "ldap"
if (builder.Configuration["Auth:Mode"]?.Equals("ldap", StringComparison.OrdinalIgnoreCase) == true)
    builder.Services.AddScoped<ILdapService, LdapService>();

// Background job for retention/cleanup
builder.Services.AddHostedService<RetentionCleanupJob>();

// ─────────────────────────────────────────────────────────────────────────────
// JWT Authentication — RS256, no clock skew
// Single RsaSecurityKey instance shared between JWT validation and TokenService.
// Key loading is deferred to DI resolution so test config overrides are honored.
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddSingleton<RsaSecurityKey>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var jwtKeyPath = config["Auth:JwtSigningKeyPath"]
        ?? throw new InvalidOperationException("Auth:JwtSigningKeyPath is required.");
    var rsa = RSA.Create();
    rsa.ImportFromPem(File.ReadAllText(jwtKeyPath));
    return new RsaSecurityKey(rsa);
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["Auth:JwtIssuer"] ?? "SecureVault",
            ValidateAudience = true,
            ValidAudience = builder.Configuration["Auth:JwtAudience"] ?? "SecureVault",
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256]
        };
        options.Events = new JwtBearerEvents
        {
            OnChallenge = ctx =>
            {
                ctx.HandleResponse();
                ctx.Response.StatusCode = 401;
                ctx.Response.ContentType = "application/json";
                return ctx.Response.WriteAsync("{\"error\":\"Unauthorized\"}");
            }
        };
    });

// Inject the signing key into JWT options after DI resolves the RsaSecurityKey
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<RsaSecurityKey>((options, key) =>
    {
        options.TokenValidationParameters.IssuerSigningKey = key;
    });

builder.Services.AddAuthorization();

// ─────────────────────────────────────────────────────────────────────────────
// Rate Limiting
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddMemoryCache();
builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));
builder.Services.Configure<ClientRateLimitOptions>(builder.Configuration.GetSection("ClientRateLimiting"));
builder.Services.AddInMemoryRateLimiting();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

// ─────────────────────────────────────────────────────────────────────────────
// CORS — restrictive; only configured origins
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        var origins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
            ?? ["http://localhost:5173"];
        policy.WithOrigins(origins)
              .AllowCredentials()
              .AllowAnyHeader()
              .WithMethods("GET", "POST", "PUT", "DELETE", "OPTIONS");
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// Controllers + Swagger
// ─────────────────────────────────────────────────────────────────────────────
builder.Services.AddControllers()
    .AddJsonOptions(opts =>
    {
        opts.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        opts.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "SecureVault API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new()
    {
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });
});

// Body size limit — 10 MB max
builder.WebHost.ConfigureKestrel(options =>
    options.Limits.MaxRequestBodySize = 10 * 1024 * 1024);

var app = builder.Build();

// ─────────────────────────────────────────────────────────────────────────────
// Middleware pipeline — exact order per TechSpec §7.2:
// Rate Limiter → CORS → Authentication → Authorization → Body Size → Controllers → Audit Logger
// ─────────────────────────────────────────────────────────────────────────────
app.UseMiddleware<GlobalExceptionMiddleware>();
app.UseSerilogRequestLogging();

app.UseIpRateLimiting();
app.UseCors();

app.UseStaticFiles();

// Setup check middleware: return 410 Gone for setup routes once initialized
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/api/v1/setup") &&
           ctx.Request.Path != "/api/v1/setup/status",
    setupApp => setupApp.Use(async (ctx, next) =>
    {
        var firstRun = ctx.RequestServices.GetRequiredService<FirstRunService>();
        if (await firstRun.IsInitializedAsync(ctx.RequestAborted))
        {
            ctx.Response.StatusCode = 410;
            await ctx.Response.WriteAsJsonAsync(new { error = "Setup already completed." });
            return;
        }
        await next();
    }));

app.UseAuthentication();
app.UseMiddleware<ApiTokenAuthMiddleware>();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.RoutePrefix = "api/docs");
}

app.MapControllers();

// API catch-all — return JSON 404 for unmatched API routes (prevents SPA HTML fallback for API calls)
app.MapFallback("api/{**path}", context =>
{
    context.Response.StatusCode = 404;
    context.Response.ContentType = "application/json";
    return context.Response.WriteAsync("{\"error\":\"Not found.\"}");
});

// SPA fallback — serve index.html for client-side routes
app.MapFallbackToFile("index.html");

app.Run();

// ─────────────────────────────────────────────────────────────────────────────
// Log scrubbing: remove sensitive field values from structured log output
// ─────────────────────────────────────────────────────────────────────────────
static object ScrubSensitiveFields(object obj)
{
    if (obj is not IDictionary<string, object> dict) return obj;

    var scrubbed = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);

    foreach (var (key, value) in dict)
    {
        if (System.Text.RegularExpressions.Regex.IsMatch(key, @"password|secret|key|token|hash",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            scrubbed[key] = "[REDACTED]";
        else
            scrubbed[key] = value;
    }

    return scrubbed;
}

// Make Program accessible for integration tests
public partial class Program { }
