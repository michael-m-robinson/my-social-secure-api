
using System.Net.Mail;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Notifications;
using My_Social_Secure_Api.Services.Notifications;
using My_Social_Secure_Api.Interfaces.Services.Notifications;

public class AdminEmailServiceTests
{
    private readonly Mock<IEmailTemplateService> _mockTemplateService;
    private readonly Mock<IEmailSender> _mockEmailSender;
    private readonly Mock<ILogger<AdminEmailService>> _mockLogger;
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
    private readonly AdminEmailService _service;

    public AdminEmailServiceTests()
    {
        _mockTemplateService = new Mock<IEmailTemplateService>();
        _mockEmailSender = new Mock<IEmailSender>();
        _mockLogger = new Mock<ILogger<AdminEmailService>>();
        _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();

        var httpContext = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation-id"
            }
        };
        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        _service = new AdminEmailService(
            _mockTemplateService.Object,
            _mockEmailSender.Object,
            _mockLogger.Object,
            _mockHttpContextAccessor.Object);
    }

    [Fact]
    public async Task SendRateLimitAlertAsync_Success_ReturnsTrue()
    {
        var user = new ApplicationUser
        {
            Id = "1",
            Email = "user@example.com",
            UserName = "test",
            FirstName = "John",
            LastName = "Doe",
            City = "Test City",
            State = "Test State",
        };
        var meta = new SendRateLimitAlertMetaData { IpAddress = "1.2.3.4", Endpoint = "/api/test" };

        _mockTemplateService.Setup(t => t.LoadTemplateAsync("RateLimitAlertTemplate", It.IsAny<Dictionary<string, string>>()))
            .ReturnsAsync("<html>template</html>");

        _mockEmailSender.Setup(e => e.SendEmailAsync(user.Email, "Rate Limit Breach Alert", It.IsAny<string>()))
            .Returns(Task.CompletedTask);

        var result = await _service.SendRateLimitAlertAsync(user, meta);

        Assert.True(result);
    }

    [Fact]
    public async Task SendRateLimitAlertAsync_ReturnsFalse_WhenTemplateMissing()
    {
        var user = new ApplicationUser
        {
            Id = "2",
            Email = "u@example.com",
            UserName = "test",
            FirstName = "Jane",
            LastName = "Doe",
            City = "Test City",
            State = "Test State",
        };
        var meta = new SendRateLimitAlertMetaData { IpAddress = "ip", Endpoint = "/e" };

        _mockTemplateService.Setup(t => t.LoadTemplateAsync(It.IsAny<string>(), It.IsAny<Dictionary<string, string>>()))
            .ThrowsAsync(new KeyNotFoundException());

        var result = await _service.SendRateLimitAlertAsync(user, meta);

        Assert.False(result);
    }

    [Fact]
    public async Task SendRateLimitAlertAsync_ReturnsFalse_WhenUserIsNull()
    {
        var meta = new SendRateLimitAlertMetaData { IpAddress = "ip", Endpoint = "/endpoint" };
        var result = await _service.SendRateLimitAlertAsync(null!, meta);
        Assert.False(result);
    }

    [Fact]
    public async Task SendRateLimitAlertAsync_ReturnsFalse_WhenSendFails()
    {
        var user = new ApplicationUser
        {
            Id = "3",
            Email = "fail@example.com",
            UserName = "fail",
            FirstName = "Mike",
            LastName = "Smith",
            City = "Test City",
            State = "Test State",
        };
        var meta = new SendRateLimitAlertMetaData { IpAddress = "0.0.0.0", Endpoint = "/x" };

        _mockTemplateService.Setup(t => t.LoadTemplateAsync(It.IsAny<string>(), It.IsAny<Dictionary<string, string>>()))
            .ReturnsAsync("body");
        _mockEmailSender.Setup(e => e.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
            .ThrowsAsync(new SmtpException("fail"));

        var result = await _service.SendRateLimitAlertAsync(user, meta);
        Assert.False(result);
    }
}
