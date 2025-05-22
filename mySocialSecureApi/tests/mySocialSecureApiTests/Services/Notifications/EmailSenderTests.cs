using System.Net.Mail;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Services.Notifications;
using My_Social_Secure_Api.Interfaces.Services.Notifications;

public class EmailSenderTests
{
    private readonly Mock<ILogger<EmailSender>> _mockLogger;
    private readonly Mock<ISmtpClient> _mockSmtpClient;
    private readonly EmailSender _service;

    public EmailSenderTests()
    {
        var mockConfig = new Mock<IConfiguration>();
        _mockLogger = new Mock<ILogger<EmailSender>>();
        var mockAccessor = new Mock<IHttpContextAccessor>();
        _mockSmtpClient = new Mock<ISmtpClient>();

        // Provide required config and environment setup
        mockConfig.Setup(c => c["Email:Smtp:Host"]).Returns("smtp.example.com");
        mockConfig.Setup(c => c["Email:Smtp:Port"]).Returns("587");
        mockConfig.Setup(c => c["Email:Smtp:Username"]).Returns("test-user");
        mockConfig.Setup(c => c["Email:Smtp:From"]).Returns("from@example.com");
        Environment.SetEnvironmentVariable("EMAIL_PASSWORD", "test-password");

        var httpContext = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "abc-123"
            }
        };
        mockAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        _service = new EmailSender(mockConfig.Object, _mockLogger.Object, mockAccessor.Object, _mockSmtpClient.Object);
    }

    [Fact]
    public async Task SendEmailAsync_CallsSmtpClient_WhenValid()
    {
        // Act
        await _service.SendEmailAsync("to@example.com", "Test Subject", "<p>Body</p>");

        // Assert
        _mockSmtpClient.Verify(c => c.SendMailAsync(It.Is<MailMessage>(m =>
            m.To[0].Address == "to@example.com" &&
            m.Subject == "Test Subject" &&
            m.Body.Contains("Body")
        )), Times.Once);
    }

    [Theory]
    [InlineData("")]
    public async Task SendEmailAsync_ThrowsArgumentNull_WhenEmailIsEmpty(string email)
    {
        await _service.SendEmailAsync(email, "subject", "message");
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("null or empty")),
                It.IsAny<ArgumentNullException>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()!
            ), Times.Once);
    }

    [Fact]
    public async Task SendEmailAsync_HandlesSmtpException_LogsError()
    {
        _mockSmtpClient
            .Setup(c => c.SendMailAsync(It.IsAny<MailMessage>()))
            .ThrowsAsync(new SmtpException("SMTP failure"));

        await _service.SendEmailAsync("to@example.com", "subject", "body");

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("SMTP error")),
                It.IsAny<SmtpException>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()!
            ), Times.Once);
    }

    [Fact]
    public async Task SendEmailAsync_HandlesUnexpectedError_LogsGenericError()
    {
        _mockSmtpClient
            .Setup(c => c.SendMailAsync(It.IsAny<MailMessage>()))
            .ThrowsAsync(new Exception("Unexpected"));

        await _service.SendEmailAsync("to@example.com", "subject", "body");

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Unexpected error")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()!
            ), Times.Once);
    }
    
    
}
