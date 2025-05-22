using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;
using My_Social_Secure_Api_Tests.Utilities;
using My_Social_Secure_Api.Models.Auth;
using Xunit;
using My_Social_Secure_Api.Services.Auth;

public class TokenParserServiceTests
{
    private readonly Mock<ILogger<TokenParserService>> _mockLogger;
    private readonly TokenParserService _service;

    public TokenParserServiceTests()
    {
        TestEnvLoader.Load();
        _mockLogger = new Mock<ILogger<TokenParserService>>();
        var jwtSettings = Options.Create(new JwtSettings
            { ExpireMinutes = 60, Audience = "test-audience", Issuer = "test-issuer" });
        _service = new TokenParserService(jwtSettings, _mockLogger.Object);
    }

    private string GenerateTestToken(string userId, string name)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("this-is-a-very-long-and-secure-test-key-123456"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, userId),
            new Claim("name", name)
        };

        var token = new JwtSecurityToken(
            issuer: "test-issuer",          // Must match jwtSettings.Issuer
            audience: "test-audience",      // Must match jwtSettings.Audience
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds
        );

        return "Bearer " + new JwtSecurityTokenHandler().WriteToken(token);
    }

    [Fact]
    public void ExtractUserInfo_ValidToken_ReturnsUserInfo()
    {
        var bearer = GenerateTestToken("abc123", "john");
        var (id, name) = _service.ExtractUserInfo(bearer);

        Assert.Equal("abc123", id);
        Assert.Equal("john", name);
    }

    [Fact]
    public void ExtractUserInfo_InvalidFormat_ReturnsAnonymous()
    {
        var (id, name) = _service.ExtractUserInfo("invalid");
        Assert.Equal("anonymous", id);
        Assert.Equal("unknown", name);
    }

    [Fact]
    public void ExtractUserInfo_EmptyToken_ReturnsAnonymous()
    {
        var (id, name) = _service.ExtractUserInfo(null);
        Assert.Equal("anonymous", id);
        Assert.Equal("unknown", name);
    }

    [Fact]
    public void ExtractUserInfo_InvalidJwt_ReturnsAnonymous()
    {
        var (id, name) = _service.ExtractUserInfo("Bearer invalid.jwt.token");
        Assert.Equal("anonymous", id);
        Assert.Equal("unknown", name);
    }

    private static string GetJwtSecretKey()
    {
        const int maxAttempts = 5;
        for (int i = 0; i < maxAttempts; i++)
        {
            var secret = Environment.GetEnvironmentVariable("JWT_SECRET_KEY");
            if (!string.IsNullOrEmpty(secret))
                return secret;

            Thread.Sleep(10); // Small delay before retry
        }

        throw new InvalidOperationException("JWT_SECRET_KEY was not loaded in time.");
    }
}