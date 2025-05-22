using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Interfaces.Services.Notifications;
using My_Social_Secure_Api.Models.Dtos.Notifications;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Notifications;
using My_Social_Secure_Api.Services.Notifications;

public class UserEmailServiceTests
{
    private readonly Mock<IEmailSender> _mockEmailSender;
    private readonly Mock<IEmailTemplateService> _mockTemplateService;
    private readonly Mock<ILogger<UserEmailService>> _mockLogger;
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
    private readonly UserEmailService _service;

    public UserEmailServiceTests()
    {
        _mockEmailSender = new Mock<IEmailSender>();
        _mockTemplateService = new Mock<IEmailTemplateService>();
        _mockLogger = new Mock<ILogger<UserEmailService>>();
        _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();

        var context = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation-id"
            }
        };
        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(context);

        _service = new UserEmailService(
            _mockEmailSender.Object,
            _mockTemplateService.Object,
            _mockLogger.Object,
            _mockHttpContextAccessor.Object);
    }

    private static ApplicationUser TestUser => new()
    {
        Id = "u1",
        Email = "user@example.com",
        UserName = "test",
        FirstName = "Test",
        LastName = "User",
        City = "Test City",
        State = "Test State",
    };

    [Fact]
    public async Task SendTwoFactorCodeEmailAsync_Success()
    {
        _mockTemplateService.Setup(t => t.LoadTemplateAsync("TwoFactorCodeTemplate", It.IsAny<Dictionary<string, string>>()))
            .ReturnsAsync("html");

        await _service.SendTwoFactorCodeEmailAsync(TestUser, new LoginMetadata());
        _mockEmailSender.Verify(x => x.SendEmailAsync("user@example.com", It.IsAny<string>(), "html"), Times.Once);
    }

    [Fact]
    public async Task SendEmailConfirmationAsync_Success()
    {
        _mockTemplateService.Setup(t => t.LoadTemplateAsync("EmailConfirmationTemplate", It.IsAny<Dictionary<string, string>>()))
            .ReturnsAsync("html");

        await _service.SendEmailConfirmationAsync(TestUser, new LoginMetadata());
        _mockEmailSender.Verify(x => x.SendEmailAsync("user@example.com", It.IsAny<string>(), "html"), Times.Once);
    }

    [Fact]
    public async Task SendPasswordChangeConfirmationAsync_Success()
    {
        _mockTemplateService.Setup(t => t.LoadTemplateAsync("PasswordChangeConfirmationTemplate", It.IsAny<Dictionary<string, string>>()))
            .ReturnsAsync("html");

        await _service.SendPasswordChangeConfirmationAsync(TestUser, new LoginMetadata());
        _mockEmailSender.Verify(x => x.SendEmailAsync("user@example.com", It.IsAny<string>(), "html"), Times.Once);
    }

    [Fact]
    public async Task SendEmailChangeConfirmationAsync_Success()
    {
        _mockTemplateService.Setup(t => t.LoadTemplateAsync("EmailChangeConfirmationTemplate", It.IsAny<Dictionary<string, string>>()))
            .ReturnsAsync("html");

        await _service.SendEmailChangeConfirmationAsync(TestUser, "new@example.com");
        _mockEmailSender.Verify(x => x.SendEmailAsync("new@example.com", It.IsAny<string>(), "html"), Times.Once);
    }

    [Fact]
    public async Task SendLoginAlertEmailAsync_Success()
    {
        _mockTemplateService.Setup(t => t.LoadTemplateAsync("LoginAlertTemplate", It.IsAny<Dictionary<string, string>>()))
            .ReturnsAsync("html");

        await _service.SendLoginAlertAsync(TestUser, new LoginAlertDto());
        _mockEmailSender.Verify(x => x.SendEmailAsync("user@example.com", It.IsAny<string>(), "html"), Times.Once);
    }
}
