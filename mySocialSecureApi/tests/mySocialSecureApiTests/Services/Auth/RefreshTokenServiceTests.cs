using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Settings;
using My_Social_Secure_Api.Services.Auth;

public class RefreshTokenServiceTests
{
    private readonly ApplicationDbContext _dbContext;
    private readonly RefreshTokenService _service;

    public RefreshTokenServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase("RefreshTokenDb")
            .Options;

        _dbContext = new ApplicationDbContext(options);
        var mockLogger = new Mock<ILogger<RefreshTokenService>>();
        var mockAccessor = new Mock<IHttpContextAccessor>();

        var context = new DefaultHttpContext();
        context.Items["X-Correlation-ID"] = "test-correlation-id";
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1");
        mockAccessor.Setup(a => a.HttpContext).Returns(context);

        var jwtSettings = Options.Create(new JwtSettings { ExpireMinutes = 60 });

        _service = new RefreshTokenService(_dbContext, mockLogger.Object, jwtSettings, mockAccessor.Object);
    }

    [Fact]
    public async Task CreateRefreshTokenAsync_CreatesAndReturnsToken()
    {
        var user = new ApplicationUser
        {
            Id = "u1",
            Email = "user@example.com",
            FirstName =  "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };

        var result = await _service.CreateRefreshTokenAsync(user);

        Assert.True(result.Success);
        Assert.NotNull(result.Data);
        Assert.False(string.IsNullOrWhiteSpace(result.Data.Token));

        var savedToken = await _dbContext.RefreshTokens.FirstOrDefaultAsync(r => r.UserId == "u1");
        Assert.NotNull(savedToken);
        Assert.Equal(user.Id, savedToken.UserId);
    }
}
