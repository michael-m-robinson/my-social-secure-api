using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

// ReSharper disable ConvertToPrimaryConstructor

namespace My_Social_Secure_Api.Services.Auth;

public class JwtTokenGenerator : IJwtTokenGenerator
{
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<JwtTokenGenerator> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;

    public JwtTokenGenerator(
        ILogger<JwtTokenGenerator> logger,
        IOptions<JwtSettings> jwtSettings,
        IHttpContextAccessor httpContextAccessor,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager)
    {
        _logger = logger;
        _jwtSettings = jwtSettings.Value ??
                       throw new ArgumentNullException(nameof(jwtSettings),
                           "JWT settings are not configured properly.");
        _httpContextAccessor = httpContextAccessor;
        _userManager = userManager;
        _roleManager = roleManager;
    }

    public ClaimsPrincipal? ValidateToken(string token, out DateTime? expiresUtc)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET_KEY") ??
                                         throw new InvalidOperationException(
                                             "JWT_SECRET_KEY environment variable is not set."));

        try
        {
            var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidAudience = _jwtSettings.Audience,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            // Safely cast to JWT and extract expiration
            var jwtToken = validatedToken as JwtSecurityToken;
            expiresUtc = jwtToken?.ValidTo;

            return principal;
        }
        catch
        {
            expiresUtc = null;
            return null;
        }
    }


    public async Task<string> GenerateToken(ApplicationUser user)
    {
        var correlationId = _httpContextAccessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("GenerateToken called. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            ValidateUser(user);

            var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName!),
            new Claim(ClaimTypes.NameIdentifier, user.Id)
        };

            var roles = await _userManager.GetRolesAsync(user);
            var permissions = new List<string>();

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));

                var roleEntity = await _roleManager.FindByNameAsync(role);
                if (roleEntity != null)
                {
                    var claimsInRole = await _roleManager.GetClaimsAsync(roleEntity);
                    foreach (var c in claimsInRole)
                    {
                        if (c.Type == "Permission" && !permissions.Contains(c.Value))
                        {
                            permissions.Add(c.Value);
                        }
                    }
                }
            }

            // Serialize permissions list into a single JSON array claim
            if (permissions.Any())
            {
                var jsonPermissions = JsonSerializer.Serialize(permissions);
                claims.Add(new Claim("Permission", jsonPermissions, JsonClaimValueTypes.JsonArray));
            }

            return GenerateJwtToken(claims, (int)_jwtSettings.ExpireMinutes);
        }
        catch (ArgumentNullException ex)
        {
            _logger.LogError(ex, "Missing user property during token generation. CorrelationId: {CorrelationId}", correlationId);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during JWT generation. CorrelationId: {CorrelationId}", correlationId);
            throw new InvalidOperationException("Failed to generate JWT token due to an unexpected error.", ex);
        }
    }


    public string GenerateTemporary2FaToken(ApplicationUser user)
    {
        var correlationId = _httpContextAccessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("GenerateTemporary2FaToken called. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            ValidateUser(user);

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id),
                new(ClaimTypes.Name, user.UserName ?? string.Empty),
                new("is2fa", "true")
            };

            return GenerateJwtToken(claims, (int)_jwtSettings.TwoFactorExpireMinutes);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating temporary 2FA token. CorrelationId: {CorrelationId}", correlationId);
            throw new InvalidOperationException("Error generating temporary 2FA token.", ex);
        }
    }

    private void ValidateUser(ApplicationUser user)
    {
        if (string.IsNullOrEmpty(user.UserName))
            throw new ArgumentNullException(nameof(user.UserName), "Username is missing.");

        if (string.IsNullOrEmpty(user.Id))
            throw new ArgumentNullException(nameof(user.Id), "User ID is missing.");
    }

    private string GenerateJwtToken(IEnumerable<Claim> claims, int expireMinutes)
    {
        if (expireMinutes <= 0)
            throw new ArgumentException("JWT expiration time must be greater than zero.");

        var secretKey = Environment.GetEnvironmentVariable("JWT_SECRET_KEY")
                        ?? throw new InvalidOperationException("JWT_SECRET_KEY environment variable is not set.");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var tokenHandler = new JwtSecurityTokenHandler();

        var identity = new ClaimsIdentity(claims);
        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: identity.Claims,
            expires: DateTime.UtcNow.AddMinutes(expireMinutes),
            signingCredentials: credentials
        );

        return tokenHandler.WriteToken(token);
    }

}