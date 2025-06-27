using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Cookies;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Interfaces.Services.Admin;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Interfaces.Services.DeviceRecognition;
using My_Social_Secure_Api.Interfaces.Services.Feedback;
using My_Social_Secure_Api.Interfaces.Services.GeoLocation;
using My_Social_Secure_Api.Interfaces.Services.LoginTracking;
using My_Social_Secure_Api.Interfaces.Services.Notifications;
using My_Social_Secure_Api.Interfaces.Services.RateLimiting;
using My_Social_Secure_Api.Interfaces.Services.Reporting;
using My_Social_Secure_Api.Interfaces.Services.Security;
using My_Social_Secure_Api.Interfaces.Services.Utilities;
using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Notifications;
using My_Social_Secure_Api.Services.Admin;
using My_Social_Secure_Api.Services.Auth;
using My_Social_Secure_Api.Services.DeviceRecognition;
using My_Social_Secure_Api.Services.Feedback;
using My_Social_Secure_Api.Services.GeoLocation;
using My_Social_Secure_Api.Services.LoginTracking;
using My_Social_Secure_Api.Services.Notifications;
using My_Social_Secure_Api.Services.RateLimiting;
using My_Social_Secure_Api.Services.Reporting;
using My_Social_Secure_Api.Services.Security;
using My_Social_Secure_Api.Services.Utilities;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using My_Social_Secure_Api.Extensions;
using My_Social_Secure_Api.Models.Settings;
using My_Social_Secure_Api.Mapping;
using My_Social_Secure_Api.Middleware;
using My_Social_Secure_Api.Swagger;
using My_Social_Secure_Api.Utilities;

// ReSharper disable UnusedVariable

// ReSharper disable UnusedParameter.Local

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    c.EnableAnnotations();
    // Add JWT Authentication
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\""
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            []
        }
    });

    c.SwaggerDoc("v2", new OpenApiInfo
    {
        Version = "v1",
        Title = "Social Secure API",
        Description = "API description"
    });

    c.OperationFilter<AddCorrelationIdHeaderOperationFilter>();
});

// Only load .env if not running in GitHub Actions or production
if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("CI")))
{
    EnvLoader.LoadEnvSafely();
}

//Configure JWT Bearer Authentication
var key = Encoding.ASCII.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET_KEY") ??
                                  throw new InvalidOperationException(
                                      "JWT_SECRET_KEY environment variable is not set."));

//PostgreSQL SQL Connection String
var connectionString = Environment.GetEnvironmentVariable("POSTGRESQL_CONNECTION_STRING") ??
                       throw new InvalidOperationException(
                           "POSTGRESSQL_CONNECTION_STRING environment variable is not set.");

// Add DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString));


// Add Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Password.RequiredLength = 12;
        options.SignIn.RequireConfirmedEmail = true;
        options.Tokens.ProviderMap.Add("Email",
            new TokenProviderDescriptor(typeof(EmailTokenProvider<ApplicationUser>)));
        options.Tokens.EmailConfirmationTokenProvider = "Email";
        options.Tokens.ChangeEmailTokenProvider = "Email";
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Configure Policies
builder.Services.AddAuthorization(options =>
{
    // General User Permissions
    options.AddPolicy("CanCalculateBenefits", policy => policy.RequireClaim("Permission", "CanCalculateBenefits"));
    options.AddPolicy("CanViewOwnProfile", policy => policy.RequireClaim("Permission", "CanViewOwnProfile"));
    options.AddPolicy("CanRequestDeletion", policy => policy.RequireClaim("Permission", "CanRequestDeletion"));
    options.AddPolicy("CanSubmitFeedback", policy => policy.RequireClaim("Permission", "CanSubmitFeedback"));

    // Manager Permissions
    options.AddPolicy("CanViewReports", policy => policy.RequireClaim("Permission", "CanViewReports"));
    options.AddPolicy("CanModerateFeedback", policy => policy.RequireClaim("Permission", "CanModerateFeedback"));

    // Admin-Only Permissions
    options.AddPolicy("CanEditUsers", policy => policy.RequireClaim("Permission", "CanEditUsers"));
    options.AddPolicy("CanAssignRoles", policy => policy.RequireClaim("Permission", "CanAssignRoles"));
    options.AddPolicy("CanViewLoginHistory", policy => policy.RequireClaim("Permission", "CanViewLoginHistory"));

    // Optional Role-Based Shortcuts (if needed)
    options.AddPolicy("ManagerOnly", policy => policy.RequireRole("Manager", "Administrator"));
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Administrator"));
});

// Configure Identity options
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
});

builder.Services.AddAutoMapper(typeof(UserRegistrationProfile).Assembly);

// Configure Rate Limiting
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));

// Add rate-limiter
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("LoginPolicy", httpContext =>
    {
        var tokenParser = httpContext.RequestServices.GetRequiredService<ITokenParserService>();
        var authHeader = httpContext.Request.Headers.Authorization.ToString();
        var (userId, _) = tokenParser.ExtractUserInfo(authHeader);

        var id = !string.IsNullOrWhiteSpace(userId) && userId != "anonymous"
            ? userId
            : httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown-ip";

        return RateLimitPartition.GetFixedWindowLimiter(id, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 5,
            Window = TimeSpan.FromMinutes(10),
            QueueLimit = 0,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst
        });
    });

    options.AddPolicy("TwoFactorPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(5),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));

    options.AddPolicy("AdminPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(10),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));

    options.AddPolicy("FeedbackSubmissionPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(3),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));

    options.AddPolicy("CalculationPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromHours(15),
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst
            }));

    options.AddPolicy("RegistrationPolicy", context =>
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown-ip";

        return RateLimitPartition.GetFixedWindowLimiter(ip, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 5,
            Window = TimeSpan.FromMinutes(10),
            QueueLimit = 0,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst
        });
    });

    options.AddPolicy("RefreshPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: s => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 20,
                Window = TimeSpan.FromMinutes(5),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 5
            }));

    options.AddPolicy("ConfirmEmailPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: s => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(5),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 5
            }));

    options.AddPolicy("ResendConfirmationPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: s => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 2,
                Window = TimeSpan.FromMinutes(10),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 1
            }));

    options.AddPolicy("LogoutPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window = TimeSpan.FromMinutes(5),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 5
            }));

    options.AddPolicy("RequestPasswordChangePolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 3,
                Window = TimeSpan.FromMinutes(10),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 1
            }));

    options.AddPolicy("ConfirmPasswordChangePolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(5),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 2
            }));

    options.AddPolicy("RequestEmailChangePolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 2,
                Window = TimeSpan.FromMinutes(10),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 1
            }));

    options.AddPolicy("ConfirmEmailChangePolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(5),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 2
            }));

    options.AddPolicy("ToggleTwoFactorPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(10),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 2
            }));

    options.AddPolicy("UpdateProfilePolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 10,
                Window = TimeSpan.FromMinutes(5),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 2
            }));

    options.AddPolicy("DeleteAccountPolicy", context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 2, // Only allow 2 delete attempts
                Window = TimeSpan.FromMinutes(10), // Every 10 minutes
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 1
            }));


    options.OnRejected = async (context, token) =>
    {
        var httpContext = context.HttpContext;
        var path = httpContext.Request.Path.Value ?? "";
        var is2Fa = path.Contains("2fa", StringComparison.OrdinalIgnoreCase);
        var isRegistration = path.Contains("register", StringComparison.OrdinalIgnoreCase);

        string breachType;
        if (is2Fa)
            breachType = "2fa";

        else if (isRegistration)
            breachType = "registration";

        else
            breachType = "login";

        var services = httpContext.RequestServices;
        var logger = services.GetRequiredService<ILogger<RateLimitingSetup>>();
        var tokenParser = services.GetRequiredService<ITokenParserService>();
        var alertTracker = services.GetRequiredService<IAlertTrackerService>();
        var adminEmailService = services.GetRequiredService<IAdminEmailService>();
        var responseWriter = services.GetRequiredService<IRateLimitResponseWriter>();
        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();

        var authHeader = httpContext.Request.Headers.Authorization.ToString();
        var (userId, _) = tokenParser.ExtractUserInfo(authHeader);

        if (alertTracker.ShouldSend(userId, breachType))
        {
            logger.LogWarning("Rate limit rejected request. Path: {Path}, IP: {Ip}, BreachType: {BreachType}",
                path,
                httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                breachType);

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                logger.LogWarning("Rate limit triggered by unknown userId: {UserId}", userId);
                await responseWriter.WriteAsync(httpContext,
                    "Too many requests detected. Please wait before trying again.", token);
                return;
            }

            var metadata = new SendRateLimitAlertMetaData
            {
                IpAddress = httpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
                Endpoint = path
            };

            var alertSent = await adminEmailService.SendRateLimitAlertAsync(user, metadata);
            if (!alertSent)
                logger.LogWarning("Failed to send rate limit alert email.");


            if (user.UserName == "unknown")
            {
                logger.LogWarning("Rate limit triggered by unknown userId: {UserId}. Using fallback user.", userId);
            }
        }

        string message;
        if (is2Fa)
            message = "Too many verification attempts. For your security, " +
                      "-please wait a bit before trying again. Need help? We're here!";

        else if (isRegistration)
            message = "We’ve noticed multiple registration attempts from your device. To protect your account, " +
                      "please wait a few minutes and try again. If you need help, feel free to contact support.";

        else
            message = "We’ve locked login temporarily due to repeated attempts. Please try again soon or reset your " +
                      "password if needed.";

        await responseWriter.WriteAsync(httpContext, message, token);
    };


    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// Password Reset: default
builder.Services.Configure<DataProtectionTokenProviderOptions>(TokenOptions.DefaultProvider,
    options => { options.TokenLifespan = TimeSpan.FromMinutes(15); });

// Change Email & Confirm Email
builder.Services.Configure<DataProtectionTokenProviderOptions>("Email",
    options => { options.TokenLifespan = TimeSpan.FromMinutes(5); });

builder.Services.Configure<DataProtectionTokenProviderOptions>("EmailConfirmation",
    options => { options.TokenLifespan = TimeSpan.FromHours(24); });

// Add Authentication
builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddCookie()
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
            ValidAudience = builder.Configuration["JwtSettings:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key)
        };

        options.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
                logger.LogError("JWT auth failed: " + context.Exception.Message);
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddHttpContextAccessor();

// Configure cookie settings
builder.Services.Configure<CookieAuthenticationOptions>(IdentityConstants.TwoFactorUserIdScheme, options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromDays(14); // Default expiration time for persistent cookies
    options.SlidingExpiration = true;
    options.LoginPath = "/Auth/Login";
    options.LogoutPath = "/Auth/Logout";
    options.AccessDeniedPath = "/Auth/AccessDenied";
    options.Cookie.Name = ".AspNetCore.Identity.TwoFactorUserId";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
});

builder.Services.Configure<BenefitSettingsModel>(
    builder.Configuration.GetSection("BenefitSettings"));

// Add Geolocation service
builder.Services.AddSingleton<IIpGeolocationService>(sp =>
{
    var env = sp.GetRequiredService<IWebHostEnvironment>();
    var dbPath = Path.Combine(env.ContentRootPath, "App_Data", "GeoLite2-City.mmdb");

    var loggerFactory = sp.GetRequiredService<ILoggerFactory>();
    var accessor = sp.GetRequiredService<IHttpContextAccessor>();
    var geoLogger = sp.GetRequiredService<ILogger<MaxMindGeolocationService>>();

    var reader = new DatabaseReaderWrapper(loggerFactory, accessor, dbPath);
    return new MaxMindGeolocationService(geoLogger, accessor, reader);
});

// Add Email service
builder.Services.Configure<SmtpSettings>(
    builder.Configuration.GetSection("Email:Smtp"));

builder.Services.AddOptions<SmtpSettings>()
    .Bind(builder.Configuration.GetSection("Email:Smtp"))
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddScoped<ISmtpClient>(provider =>
{
    var smtpSettings = provider.GetRequiredService<IOptions<SmtpSettings>>().Value;
    var logger = provider.GetRequiredService<ILogger<SmtpClientWrapper>>();

    var password = Environment.GetEnvironmentVariable("EMAIL_PASSWORD")
                   ?? throw new InvalidOperationException("EMAIL_PASSWORD environment variable is not set.");

    var smtpClient = new SmtpClient(smtpSettings.Host, smtpSettings.Port)
    {
        Credentials = new NetworkCredential(smtpSettings.Username, password),
        EnableSsl = true
    };

    return new SmtpClientWrapper(
        smtpSettings.Host,
        smtpSettings.Port,
        smtpSettings.Username,
        password,
        logger);
});

// Add custom services to the container.
builder.Services.AddScoped<IEmailSender, EmailSender>();
builder.Services.AddScoped<IJwtTokenGenerator, JwtTokenGenerator>();
builder.Services.AddScoped<IEmailTemplateService, EmailTemplateService>();
builder.Services.AddScoped<IUserEmailService, UserEmailService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IAccountService, AccountService>();
builder.Services.AddScoped<ILoginAlertService, LoginAlertService>();
builder.Services.AddScoped<IDeviceRecognitionService, DeviceRecognitionService>();
builder.Services.AddScoped<ILoginHistoryService, LoginHistoryService>();
builder.Services.AddScoped<IAdminEmailService, AdminEmailService>();
builder.Services.AddScoped<ITokenParserService, TokenParserService>();
builder.Services.AddScoped<IRateLimitResponseWriter, RateLimitResponseWriter>();
builder.Services.AddScoped<IUrlBuilderService, UrlBuilderService>();
builder.Services.AddScoped<IRefreshTokenService, RefreshTokenService>();
builder.Services.AddScoped<IAdminService, AdminService>();
builder.Services.AddScoped<IFeedbackService, FeedbackService>();
builder.Services.AddScoped<IReportService, ReportService>();
builder.Services.AddScoped<ITokenBundleService, TokenBundleService>();
builder.Services.AddSingleton<IAlertTrackerService, AlertTrackerService>();
builder.Services.AddSingleton<IGeoLite2Downloader, GeoLite2Downloader>();
builder.Services.AddSingleton<IClock, SystemClock>();

// Register the PwnedPasswordService with HttpClient
builder.Services.AddHttpClient<PwnedPasswordService>();

// Register GeoLite2Extractor with HttpClient
builder.Services.AddHttpClient<GeoLite2Downloader>();

// Load the certificate
var kestrelCertPath = Environment.GetEnvironmentVariable("SSL_CERT_PATH")
                      ?? Path.Combine(builder.Environment.ContentRootPath, "App_Data", "localhost.pfx");
var kestrelCertPassword = Environment.GetEnvironmentVariable("SSL_CERT_PASSWORD") ?? "devpass";

if (File.Exists(kestrelCertPath))
{
    var cert = new X509Certificate2(kestrelCertPath, kestrelCertPassword);

    builder.WebHost.ConfigureKestrel(options =>
    {
        options.Listen(IPAddress.Any, 7119, listenOptions => { listenOptions.UseHttps(cert); });
    });
}
else
{
    Console.WriteLine($"⚠️ WARNING: Certificate not found at {kestrelCertPath}. HTTPS is not configured.");
}


builder.Services.AddCors();

builder.Services.AddCors(options =>
{
    options.AddPolicy("DefaultPolicy", corsPolicyBuilder =>
    {
        corsPolicyBuilder.WithOrigins("https://mysocialsecure.com")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});


var app = builder.Build();

app.MapGet("/", () => "mySocialSecure Disability API");

app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v2/swagger.json", "mySocialSecure API v2");
    options.RoutePrefix = "docs"; // Access it at /docs instead of /
});

app.UseWhen(context => context.Request.Path.StartsWithSegments("/docs"), appBuilder =>
{
    appBuilder.UseAuthentication();
    appBuilder.UseAuthorization();
});


using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var dbContext = services.GetRequiredService<ApplicationDbContext>();

    if (dbContext.Database.IsRelational())
    {
        await dbContext.Database.MigrateAsync();
    }
    else
    {
        await dbContext.Database.EnsureCreatedAsync();
    }

    await RoleClaimAndAdminSeeder.SeedRolesAndClaimsAsync(services);
}

app.ConfigureExceptionHandler(app.Services.GetRequiredService<ILoggerFactory>());
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseHttpsRedirection();
app.UseHsts();
app.UseRouting();
app.UseCors("DefaultPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.MapControllers();

app.Run();

public static class RoleClaimAndAdminSeeder
{
    public static async Task SeedRolesAndClaimsAsync(IServiceProvider serviceProvider)
    {
        var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var rolesWithClaims = new Dictionary<string, List<Claim>>
        {
            {
                "User", [
                    new Claim("Permission", "CanCalculateBenefits"),
                    new Claim("Permission", "CanViewOwnProfile"),
                    new Claim("Permission", "CanRequestDeletion"),
                    new Claim("Permission", "CanSubmitFeedback")
                ]
            },
            {
                "Manager", [
                    new Claim("Permission", "CanViewReports"),
                    new Claim("Permission", "CanModerateFeedback")
                ]
            },
            {
                "Administrator", [
                    new Claim("Permission", "CanViewReports"),
                    new Claim("Permission", "CanModerateFeedback"),
                    new Claim("Permission", "CanEditUsers"),
                    new Claim("Permission", "CanAssignRoles"),
                    new Claim("Permission", "CanViewLoginHistory")
                ]
            }
        };

        foreach (var role in rolesWithClaims.Keys)
        {
            // Create role if it doesn't exist
            if (!await roleManager.RoleExistsAsync(role))
                await roleManager.CreateAsync(new IdentityRole(role));

            var identityRole = await roleManager.FindByNameAsync(role);
            var existingClaims = await roleManager.GetClaimsAsync(identityRole!);

            // Add missing claims
            foreach (var claim in rolesWithClaims[role])
            {
                if (!existingClaims.Any(c => c.Type == claim.Type && c.Value == claim.Value))
                    await roleManager.AddClaimAsync(identityRole!, claim);
            }
        }

        var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var adminEmail = Environment.GetEnvironmentVariable("DEFAULT_ADMIN_EMAIL")
                         ?? "admin@mysocialsecure.com";

        var adminPassword = Environment.GetEnvironmentVariable("DEFAULT_ADMIN_PASSWORD");

        if (string.IsNullOrWhiteSpace(adminPassword))
            throw new Exception("DEFAULT_ADMIN_PASSWORD is not set.");

        var adminUser = await userManager.FindByEmailAsync(adminEmail);

        if (adminUser == null)
        {
            adminUser = new ApplicationUser
            {
                UserName = "Administrator",
                FirstName = "Admin",
                LastName = "User",
                Email = adminEmail,
                EmailConfirmed = true,
                City = "New York",
                State = "NY",
            };

            if (string.IsNullOrWhiteSpace(adminPassword))
                throw new Exception("DEFAULT_ADMIN_PASSWORD is not set.");

            var created = await userManager.CreateAsync(adminUser, adminPassword);
            if (created.Succeeded)
            {
                await userManager.AddToRoleAsync(adminUser, "Administrator");
            }
        }
        else if (!await userManager.IsInRoleAsync(adminUser, "Administrator"))
        {
            await userManager.AddToRoleAsync(adminUser, "Administrator");
        }
    }
}

public abstract class RateLimitingSetup
{
}

public partial class Program
{
}