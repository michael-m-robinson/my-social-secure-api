using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Models.Auth;
// ReSharper disable ConvertToPrimaryConstructor

namespace My_Social_Secure_Api.Services.Auth;

public class TokenParserService : ITokenParserService
{
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<TokenParserService> _logger;

    public TokenParserService(
        IOptions<JwtSettings> jwtSettings,
        ILogger<TokenParserService> logger)
    {
        _jwtSettings = jwtSettings.Value ?? throw new ArgumentNullException(nameof(jwtSettings));
        _logger = logger;
    }


    public (string UserId, string UserName) ExtractUserInfo(string? bearerToken)
    {
        if (!IsValidBearerToken(bearerToken))
        {
            _logger.LogWarning("Invalid or missing bearer token received.");
            return ("anonymous", "unknown");
        }

        var tokenStr = ExtractTokenString(bearerToken!);

        try
        {
            var jwtToken = ValidateJwtToken(tokenStr);
            return ExtractClaims(jwtToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to validate JWT or extract claims.");
            return ("anonymous", "unknown");
        }
    }

    private bool IsValidBearerToken(string? bearerToken)
    {
        return !string.IsNullOrWhiteSpace(bearerToken) && bearerToken.StartsWith("Bearer ");
    }

    private string ExtractTokenString(string bearerToken)
    {
        return bearerToken["Bearer ".Length..].Trim();
    }

    private JwtSecurityToken ValidateJwtToken(string tokenStr)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var keyString = Environment.GetEnvironmentVariable("JWT_SECRET_KEY")
                        ?? throw new InvalidOperationException("JWT_SECRET_KEY environment variable is not set.");
        
        if (string.IsNullOrEmpty(keyString))
        {
            _logger.LogCritical("JWT_SECRET_KEY environment variable is not set.");
            throw new InvalidOperationException("JWT_SECRET_KEY environment variable is not set.");
        }

        var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(keyString));

        tokenHandler.ValidateToken(tokenStr, new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _jwtSettings.Issuer,
            ValidAudience = _jwtSettings.Audience,
            IssuerSigningKey = key
        }, out var validatedToken);

        return (JwtSecurityToken)validatedToken;
    }

    private (string UserId, string UserName) ExtractClaims(JwtSecurityToken jwtToken)
    {
        var userId = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value ?? "anonymous";
        var userName = jwtToken.Claims.FirstOrDefault(c =>
            c.Type == ClaimTypes.Name ||
            c.Type == "username" ||
            c.Type == JwtRegisteredClaimNames.UniqueName ||
            c.Type == JwtRegisteredClaimNames.Name ||
            c.Type == "name")?.Value ?? "unknown";

        return (userId, userName);
    }
}
