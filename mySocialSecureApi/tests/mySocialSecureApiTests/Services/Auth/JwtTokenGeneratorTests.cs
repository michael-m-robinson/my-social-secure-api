using Microsoft.AspNetCore.Http;
using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Services.Auth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace My_Social_Secure_Api_Tests.Services.Auth;

public class JwtTokenGeneratorTests
{
    private readonly Mock<ILogger<JwtTokenGenerator>> _loggerMock;
    private readonly JwtSettings _jwtSettings;
    private readonly JwtTokenGenerator _tokenGenerator;

    public JwtTokenGeneratorTests()
    {
        _loggerMock = new Mock<ILogger<JwtTokenGenerator>>();
        _jwtSettings = new JwtSettings { ExpireMinutes = 15, TwoFactorExpireMinutes = 5 };
        var options = Options.Create(_jwtSettings);
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        Environment.SetEnvironmentVariable("JWT_SECRET_KEY", "supersecretkey1234567890_supersecure");


        _tokenGenerator = new JwtTokenGenerator(_loggerMock.Object, options, mockHttpContextAccessor.Object);
    }

    [Fact]
    public void GenerateToken_ReturnsToken_ForValidUser()
    {
        var user = new ApplicationUser
        {
            Id = "123",
            UserName = "test-user",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };
        var token = _tokenGenerator.GenerateToken(user);

        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    [Fact]
    public void GenerateTemporary2FaToken_ReturnsToken_ForValidUser()
    {
        var user = new ApplicationUser
        {
            Id = "456",
            UserName = "2fa-user",
            FirstName = "Jane",
            LastName = "Smith",
            City = "Los Angeles",
            State = "CA",
        };
        var token = _tokenGenerator.GenerateTemporary2FaToken(user);

        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    [Fact]
    public void GenerateToken_ThrowsException_WhenUserNameMissing()
    {
        var user = new ApplicationUser
        {
            Id = "123",
            UserName = String.Empty,
            FirstName = "Test",
            LastName = "User",
            City = "Test City",
            State = "Test State",
        };

        var ex = Assert.Throws<ArgumentNullException>(() => _tokenGenerator.GenerateToken(user));
        Assert.Contains("Username is missing.", ex.Message);
    }

    [Fact]
    public void GenerateToken_ThrowsException_WhenUserIdMissing()
    {
        var user = new ApplicationUser
        {
            Id = string.Empty,
            UserName = "test-user",
            FirstName = "Test",
            LastName = "User",
            City = "Test City",
            State = "Test State",
        };

        var ex = Assert.Throws<ArgumentNullException>(() => _tokenGenerator.GenerateToken(user));
        Assert.Contains("User ID is missing.", ex.Message);
    }

    [Fact]
    public void GenerateToken_ThrowsException_WhenJwtKeyMissing()
    {
        Environment.SetEnvironmentVariable("JWT_SECRET_KEY", null);
        var options = Options.Create(_jwtSettings);
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var generator = new JwtTokenGenerator(_loggerMock.Object, options, mockHttpContextAccessor.Object);
        var user = new ApplicationUser
        {
            Id = "789",
            UserName = "fail-user",
            FirstName = "Fail",
            LastName = "User",
            City = "Fail City",
            State = "Fail State",
        };

        var ex = Assert.Throws<InvalidOperationException>(() => generator.GenerateToken(user));
        Assert.Contains("Failed to generate JWT token due to an unexpected error.", ex.Message);

        // Reset environment for other tests
        Environment.SetEnvironmentVariable("JWT_SECRET_KEY", "supersecretkey1234567890_supersecure");

    }
}