using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Services.Notifications;

namespace My_Social_Secure_Api.Tests.Services.Notifications;

public class EmailTemplateServiceTests
{
    private readonly Mock<IWebHostEnvironment> _mockEnv;
    private readonly Mock<ILogger<EmailTemplateService>> _mockLogger;
    private readonly Mock<IHttpContextAccessor> _mockAccessor;
    private readonly EmailTemplateService _service;

    public EmailTemplateServiceTests()
    {
        _mockEnv = new Mock<IWebHostEnvironment>();
        _mockLogger = new Mock<ILogger<EmailTemplateService>>();
        _mockAccessor = new Mock<IHttpContextAccessor>();

        var context = new DefaultHttpContext();
        context.Items["X-Correlation-ID"] = "test-correlation-id";
        _mockAccessor.Setup(x => x.HttpContext).Returns(context);

        _service = new EmailTemplateService(_mockEnv.Object, _mockLogger.Object, _mockAccessor.Object);
    }

    [Fact]
    public async Task LoadTemplateAsync_ReturnsProcessedTemplate()
    {
        // Arrange
        var tempDir = Path.Combine(Path.GetTempPath(), "TestTemplates");
        var templateDir = Path.Combine(tempDir, "EmailTemplates");
        Directory.CreateDirectory(templateDir);

        var templateName = "test-template";
        var filePath = Path.Combine(templateDir, templateName);
        await File.WriteAllTextAsync(filePath, "Hello {{Name}}!");

        _mockEnv.Setup(e => e.ContentRootPath).Returns(tempDir);

        // Act
        var result = await _service.LoadTemplateAsync(
            templateName,
            new Dictionary<string, string> { { "Name", "Mike" } },
            _mockAccessor.Object,
            _mockLogger.Object);

        // Assert
        Assert.Equal("Hello Mike!", result);

        // Cleanup
        File.Delete(filePath);
    }

    [Fact]
    public async Task LoadTemplateAsync_Throws_WhenReplacementsNull()
    {
        _mockEnv.Setup(e => e.WebRootPath).Returns("/fake");

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            _service.LoadTemplateAsync("file.html", null!, _mockAccessor.Object, _mockLogger.Object));
    }
    
    [Fact]
    public async Task LoadTemplateAsync_Throws_FileNotFound_WhenTemplateMissing()
    {
        _mockEnv.Setup(e => e.ContentRootPath).Returns("/fake/path");

        var ex = await Assert.ThrowsAsync<FileNotFoundException>(() =>
            _service.LoadTemplateAsync("missing", new Dictionary<string, string>(), _mockAccessor.Object, _mockLogger.Object));

        Assert.Contains("Email template not found", ex.Message);
    }

}

