using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Services.LoginTracking;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Models.Identity;
using Microsoft.EntityFrameworkCore;

public class LoginHistoryServiceTests
{
    private readonly ApplicationDbContext _dbContext;
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
    private readonly Mock<ILogger<LoginHistoryService>> _mockLogger;
    private readonly LoginHistoryService _service;

    public LoginHistoryServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase("LoginHistoryServiceTests")
            .Options;

        _dbContext = new ApplicationDbContext(options);
        _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        _mockLogger = new Mock<ILogger<LoginHistoryService>>();

        _service = new LoginHistoryService(_dbContext, _mockLogger.Object, _mockHttpContextAccessor.Object);
    }

    [Fact]
    public async Task LogLoginAsync_SavesLoginEntry()
    {
        var user = new ApplicationUser
        {
            Id = "u1",
            Email = "user@example.com",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };
        var ip = "192.168.1.1";
        var device = "Mozilla/5.0";
        var location = "New York, NY";

        await _service.RecordLoginAsync(user, ip, device, location);

        var entry = await _dbContext.LoginHistories.FirstOrDefaultAsync();

        Assert.NotNull(entry);
        Assert.Equal("u1", entry.UserId);
        Assert.Equal(ip, entry.IpAddress);
        Assert.Equal(device, entry.Device);
        Assert.Equal(location, entry.Location);
    }

    [Fact]
    public async Task LogLoginAsync_HandlesNullUserGracefully()
    {
        var result = await Record.ExceptionAsync(() => _service.RecordLoginAsync(null!, "127.0.0.1", "agent", "location"));
        Assert.Null(result);
    }

    [Fact]
    public async Task LogLoginAsync_HandlesExceptionGracefully()
    {
        var service = new LoginHistoryService(null!, _mockLogger.Object, _mockHttpContextAccessor.Object);
        var result = await Record.ExceptionAsync(() => service.RecordLoginAsync(new ApplicationUser
        {
            FirstName = null!,
            LastName = null!,
            City = null!,
            State = null!
        }, "ip", "agent", "location"));
        Assert.Null(result); // Should log and suppress error
    }
}
