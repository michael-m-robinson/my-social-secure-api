using System.Net.Mail;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Interfaces.Services.GeoLocation;
using My_Social_Secure_Api.Services.Security;
using My_Social_Secure_Api.Interfaces.Services.Notifications;
using My_Social_Secure_Api.Interfaces.Services.DeviceRecognition;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Dtos.Notifications;
using My_Social_Secure_Api.Models.Entities.Auth;
using Microsoft.EntityFrameworkCore;
using My_Social_Secure_Api.Data;

public class LoginAlertServiceTests
{
    [Fact]
    public async Task HandleLoginAlertAsync_CreatesAlertForNewDevice()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString()).Options;
        await using var db = new ApplicationDbContext(options);

        var mockAccessor = new Mock<IHttpContextAccessor>();
        var mockContext = new DefaultHttpContext
        {
            Connection =
            {
                RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1")
            }
        };
        mockContext.Request.Headers["User-Agent"] = "UnitTestBrowser";
        mockContext.Items["X-Correlation-ID"] = "test-correlation";
        mockAccessor.Setup(x => x.HttpContext).Returns(mockContext);

        var mockEmailService = new Mock<IUserEmailService>();
        var mockGeo = new Mock<IIpGeolocationService>();
        var mockDevice = new Mock<IDeviceRecognitionService>();
        var mockLogger = new Mock<ILogger<LoginAlertService>>();

        var user = new ApplicationUser
        {
            Id = "user1",
            UserName = "test-user",
            Email = "test@example.com",
            FirstName = "Test",
            LastName = "User",
            City = "Test City",
            State = "Test State",
        };

        mockGeo.Setup(g => g.GetLocationAsync(It.IsAny<string>())).ReturnsAsync("USA");
        mockDevice.Setup(d => d.IsKnownDeviceAsync(user, "127.0.0.1", "UnitTestBrowser")).ReturnsAsync(false);

        var service = new LoginAlertService(db, mockAccessor.Object, mockEmailService.Object, mockGeo.Object, mockDevice.Object, mockLogger.Object);

        await service.HandleLoginAlertAsync(user, "example.com");

        mockEmailService.Verify(e => e.SendLoginAlertAsync(It.IsAny<ApplicationUser>(), It.IsAny<LoginAlertDto>()), Times.Once);

        var savedAlert = await db.LoginAlerts.FirstOrDefaultAsync();
        Assert.NotNull(savedAlert);
        Assert.Equal("127.0.0.1", savedAlert.IpAddress);
        Assert.Equal("user1", savedAlert.UserId);
    }

    [Fact]
    public async Task HandleLoginAlertAsync_AbortsIfHttpContextIsNull()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString()).Options;
        await using var db = new ApplicationDbContext(options);

        var mockAccessor = new Mock<IHttpContextAccessor>();
        mockAccessor.Setup(x => x.HttpContext).Returns<HttpContext>(null!);

        var mockEmailService = new Mock<IUserEmailService>();
        var mockGeo = new Mock<IIpGeolocationService>();
        var mockDevice = new Mock<IDeviceRecognitionService>();
        var mockLogger = new Mock<ILogger<LoginAlertService>>();

        var user = new ApplicationUser
        {
            Id = "user2",
            UserName = "nohttpcontext",
            FirstName = "Test",
            LastName = "User",
            City = ":Test City",
            State = "Test State",
        };

        var service = new LoginAlertService(db, mockAccessor.Object, mockEmailService.Object, mockGeo.Object, mockDevice.Object, mockLogger.Object);

        await service.HandleLoginAlertAsync(user, "example.com");

        Assert.Empty(db.LoginAlerts);
    }

    [Fact]
    public async Task HandleLoginAlertAsync_SkipsIfAlertExists()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString()).Options;
        await using var db = new ApplicationDbContext(options);

        db.LoginAlerts.Add(new LoginAlertModel
            { UserId = "user3", IpAddress = "127.0.0.1", LoginTime = DateTime.UtcNow });
        await db.SaveChangesAsync();

        var mockAccessor = new Mock<IHttpContextAccessor>();
        var mockContext = new DefaultHttpContext
        {
            Connection =
            {
                RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1")
            }
        };
        mockContext.Request.Headers["User-Agent"] = "TestAgent";
        mockContext.Items["X-Correlation-ID"] = "test";
        mockAccessor.Setup(x => x.HttpContext).Returns(mockContext);

        var mockEmailService = new Mock<IUserEmailService>();
        var mockGeo = new Mock<IIpGeolocationService>();
        var mockDevice = new Mock<IDeviceRecognitionService>();
        var mockLogger = new Mock<ILogger<LoginAlertService>>();

        var user = new ApplicationUser
        {
            Id = "user3",
            UserName = "duplicate",
            Email = "test@example.com",
            FirstName = "Test",
            LastName = "User",
            City = "Test City",
            State = "Test State",
        };

        var service = new LoginAlertService(db, mockAccessor.Object, mockEmailService.Object, mockGeo.Object, mockDevice.Object, mockLogger.Object);

        await service.HandleLoginAlertAsync(user, "example.com");

        mockEmailService.Verify(x => x.SendLoginAlertAsync(It.IsAny<ApplicationUser>(), It.IsAny<LoginAlertDto>()), Times.Never);
    }

    [Theory]
    [InlineData(typeof(DbUpdateException))]
    [InlineData(typeof(HttpRequestException))]
    [InlineData(typeof(SmtpException))]
    [InlineData(typeof(ArgumentException))]
    [InlineData(typeof(InvalidOperationException))]
    [InlineData(typeof(Exception))]
    public async Task HandleLoginAlertAsync_LogsExpectedErrors(Type exceptionType)
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString()).Options;
        await using var db = new ApplicationDbContext(options);

        var mockAccessor = new Mock<IHttpContextAccessor>();
        var mockContext = new DefaultHttpContext
        {
            Connection =
            {
                RemoteIpAddress = System.Net.IPAddress.Parse("127.0.0.1")
            }
        };
        mockContext.Request.Headers["User-Agent"] = "ThrowAgent";
        mockContext.Items["X-Correlation-ID"] = "test-error";
        mockAccessor.Setup(x => x.HttpContext).Returns(mockContext);

        var mockEmailService = new Mock<IUserEmailService>();
        var mockGeo = new Mock<IIpGeolocationService>();
        var mockDevice = new Mock<IDeviceRecognitionService>();
        var mockLogger = new Mock<ILogger<LoginAlertService>>();

        var user = new ApplicationUser
        {
            Id = "user-error",
            UserName = "error-user",
            FirstName = "Test",
            LastName = "User",
            City = "Test City",
            State = "Test State",
        };

        mockGeo.Setup(g => g.GetLocationAsync(It.IsAny<string>())).Throws((Exception)Activator.CreateInstance(exceptionType)!);

        var service = new LoginAlertService(db, mockAccessor.Object, mockEmailService.Object, mockGeo.Object, mockDevice.Object, mockLogger.Object);

        var ex = await Record.ExceptionAsync(() => service.HandleLoginAlertAsync(user, "example.com"));

        Assert.Null(ex); // It should catch internally
        mockLogger.Verify(l => l.Log(
            LogLevel.Error,
            It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((v, t) => true),
            It.Is<Exception>(e => e.GetType() == exceptionType),
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()
        ), Times.Once);
    }
}
