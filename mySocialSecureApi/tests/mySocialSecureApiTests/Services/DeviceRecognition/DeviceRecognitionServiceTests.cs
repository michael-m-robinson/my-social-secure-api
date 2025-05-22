using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Entities.DeviceRecognition;
using My_Social_Secure_Api.Services.DeviceRecognition;

public class DeviceRecognitionServiceTests
{
    private readonly ApplicationDbContext _dbContext;
    private readonly Mock<ILogger<DeviceRecognitionService>> _mockLogger;
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
    private readonly DeviceRecognitionService _service;

    public DeviceRecognitionServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase("DeviceRecognitionServiceTests")
            .Options;

        _dbContext = new ApplicationDbContext(options);
        _mockLogger = new Mock<ILogger<DeviceRecognitionService>>();
        _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();

        var context = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation-id"
            }
        };
        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(context);

        _service = new DeviceRecognitionService(_dbContext, _mockLogger.Object, _mockHttpContextAccessor.Object);
    }

    [Fact]
    public async Task IsKnownDeviceAsync_ReturnsTrue_WhenDeviceExists()
    {
        var user = new ApplicationUser
        {
            Id = "user1",
            FirstName = "John",
            LastName = "Doe",
            City = "New York",
            State = "NY",
        };
        var fingerprint = _service.GetType().GetMethod("GenerateFingerprint", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .Invoke(_service, ["ip", "agent"])!.ToString();

        _dbContext.DeviceRecognitions.Add(new DeviceRecognitionModel() { UserId = user.Id, DeviceFingerprint = fingerprint!, LastSeen = DateTime.UtcNow });
        await _dbContext.SaveChangesAsync();

        var result = await _service.IsKnownDeviceAsync(user, "ip", "agent");
        Assert.True(result);
    }

    [Fact]
    public async Task IsKnownDeviceAsync_ReturnsFalse_WhenDeviceDoesNotExist()
    {
        var user = new ApplicationUser
        {
            Id = "user2",
            FirstName = "Jane",
            LastName = "Smith",
            City = "Los Angeles",
            State = "CA",
        };
        var result = await _service.IsKnownDeviceAsync(user, "x", "y");
        Assert.False(result);
    }

    [Fact]
    public async Task RegisterDeviceAsync_AddsNewRecord()
    {
        var user = new ApplicationUser
        {
            Id = "user3",
            FirstName = "Bob",
            LastName = "Builder",
            City = "Builder City",
            State = "BC",
        };
        await _service.RegisterDeviceAsync(user, "ip1", "agent1", "location1");

        var entry = await _dbContext.DeviceRecognitions.FirstOrDefaultAsync(d => d.UserId == "user3");
        Assert.NotNull(entry);
        Assert.Equal("user3", entry.UserId);
    }

    [Fact]
    public async Task RegisterDeviceAsync_UpdatesLastSeen()
    {
        var user = new ApplicationUser
        {
            Id = "user4",
            FirstName = "Alice",
            LastName = "Wonderland",
            City = "Wonderland",
            State = "Fantasy",
        };
        await _service.RegisterDeviceAsync(user, "ip4", "agent4", "loc");
        var original = await _dbContext.DeviceRecognitions.FirstOrDefaultAsync(d => d.UserId == "user4");

        var originalDate = original!.LastSeen;
        await Task.Delay(1000);
        await _service.RegisterDeviceAsync(user, "ip4", "agent4", "loc");

        var updated = await _dbContext.DeviceRecognitions.FirstOrDefaultAsync(d => d.UserId == "user4");
        Assert.True(updated!.LastSeen > originalDate);
    }
}
