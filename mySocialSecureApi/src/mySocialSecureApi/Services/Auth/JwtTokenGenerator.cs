using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Identity;
// ReSharper disable ConvertToPrimaryConstructor

namespace My_Social_Secure_Api.Services.Auth;

public class JwtTokenGenerator : IJwtTokenGenerator
{
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<JwtTokenGenerator> _logger;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public JwtTokenGenerator(
        ILogger<JwtTokenGenerator> logger,
        IOptions<JwtSettings> jwtSettings,
        IHttpContextAccessor httpContextAccessor)
    {
        _logger = logger;
        _jwtSettings = jwtSettings.Value ?? throw new ArgumentNullException(nameof(jwtSettings), "JWT settings are not configured properly.");
        _httpContextAccessor = httpContextAccessor;
    }

    public string GenerateToken(ApplicationUser user)
    {
        var correlationId = _httpContextAccessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString();
        _logger.LogInformation("GenerateToken called. CorrelationId: {CorrelationId}", correlationId);

        try
        {
            ValidateUser(user);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };

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

        var token = new JwtSecurityToken(
            _jwtSettings.Issuer,
            _jwtSettings.Audience,
            claims,
            expires: DateTime.UtcNow.AddMinutes(expireMinutes),
            signingCredentials: credentials
        );

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
        _logger.LogInformation("JWT token generated at {TimeUtc}.", DateTime.UtcNow);

        return tokenString;
    }
}
