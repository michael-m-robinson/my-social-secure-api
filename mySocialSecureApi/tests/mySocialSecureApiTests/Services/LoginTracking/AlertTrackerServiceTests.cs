using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Interfaces.Services.Utilities;
using My_Social_Secure_Api.Services.LoginTracking;

public class AlertTrackerServiceTests
{
    [Fact]
    public void ShouldSend_ReturnsTrue_IfNoPriorAlert()
    {
        var mockLogger = new Mock<ILogger<AlertTrackerService>>();
        var mockClock = new Mock<IClock>();
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var now = DateTime.Now;
        mockClock.Setup(c => c.UtcNow).Returns(() => now);
        

        var service = new AlertTrackerService(mockClock.Object, mockLogger.Object, mockHttpContextAccessor.Object);
        var result = service.ShouldSend("user1", "breach1");

        Assert.True(result);
    }

    [Fact]
    public void ShouldSend_ReturnsFalse_IfSentRecently()
    {
        var mockLogger = new Mock<ILogger<AlertTrackerService>>();
        var mockClock = new Mock<IClock>();
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var now = DateTime.UtcNow;
        mockClock.Setup(c => c.UtcNow).Returns(() => now);


        var service = new AlertTrackerService(mockClock.Object, mockLogger.Object, mockHttpContextAccessor.Object);
        
        var first = service.ShouldSend("user1", "breach1");
        now = now.AddMinutes(5);
        var second = service.ShouldSend("user1", "breach1");

        Assert.True(first);
        Assert.False(second);
    }

    [Fact]
    public void ShouldSend_ReturnsTrue_IfTimeHasElapsed()
    {
        var mockLogger = new Mock<ILogger<AlertTrackerService>>();
        var mockClock = new Mock<IClock>();
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var now = DateTime.UtcNow;
        mockClock.SetupSequence(c => c.UtcNow)
            .Returns(() => now)
            .Returns(() => now.AddMinutes(15));

        var service = new AlertTrackerService(mockClock.Object, mockLogger.Object, mockHttpContextAccessor.Object);
        var first = service.ShouldSend("user1", "breach1");
        var second = service.ShouldSend("user1", "breach1");

        Assert.True(first);
        Assert.True(second);
    }

    [Fact]
    public void ShouldSend_MissingUserId_Throws()
    {
        var mockLogger = new Mock<ILogger<AlertTrackerService>>();
        var mockClock = new Mock<IClock>();
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var service = new AlertTrackerService(mockClock.Object, mockLogger.Object, mockHttpContextAccessor.Object);
        Assert.False(service.ShouldSend(null!, "type"));
    }

    [Fact]
    public void ShouldSend_MissingType_Throws()
    {
        var mockLogger = new Mock<ILogger<AlertTrackerService>>();
        var mockClock = new Mock<IClock>();
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();
        var service = new AlertTrackerService(mockClock.Object, mockLogger.Object, mockHttpContextAccessor.Object);
        Assert.False(service.ShouldSend("user", null!));
    }
}
