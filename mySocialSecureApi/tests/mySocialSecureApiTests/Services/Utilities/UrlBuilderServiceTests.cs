using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Models.Account;
using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Services.Utilities;

public class UrlBuilderServiceTests
{
    private readonly Mock<ILogger<UrlBuilderService>> _loggerMock = new();
    private readonly Mock<IHttpContextAccessor> _httpContextAccessorMock = new();

    public UrlBuilderServiceTests()
    {
        var httpContext = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation"
            }
        };
        _httpContextAccessorMock.Setup(x => x.HttpContext).Returns(httpContext);
    }

    [Fact]
    public void BuildEmailChangeCallbackUrl_ReturnsCorrectUrl()
    {
        var service = new UrlBuilderService(_loggerMock.Object, _httpContextAccessorMock.Object);

        var request = new EmailChangeRequest
        {
            Scheme = "https",
            Host = new HostString("example.com"),
            UserId = "user123",
            NewEmail = "test@example.com",
            Token = "abc123"
        };

        var result = service.BuildEmailChangeCallbackUrl(request);

        Assert.Contains("userId=user123", result);
        Assert.Contains("newEmail=test%40example.com", result);
        Assert.Contains("token=abc123", result);
    }

    [Fact]
    public void BuildTwoFactorCallbackUrl_ReturnsCorrectUrl()
    {
        var service = new UrlBuilderService(_loggerMock.Object, _httpContextAccessorMock.Object);

        var request = new TwoFactorAuthRequest
        {
            Scheme = "https",
            Host = new HostString("example.com"),
            UserName = "tester",
            Code = "123456",
            RememberMe = true
        };

        var result = service.BuildTwoFactorCallbackUrl(request);

        Assert.Contains("userName=tester", result);
        Assert.Contains("twoFactorCode=123456", result);
        Assert.Contains("rememberMe=true", result);
    }

    [Fact]
    public void BuildEmailConfirmationUrl_ReturnsCorrectUrl()
    {
        var service = new UrlBuilderService(_loggerMock.Object, _httpContextAccessorMock.Object);

        var request = new EmailConfirmationRequest
        {
            Scheme = "https",
            Host = new HostString("example.com"),
            UserId = "user1",
            Token = "token-value"
        };

        var result = service.BuildEmailConfirmationUrl(request);

        Assert.Contains("userId=user1", result);
        Assert.Contains("token=token-value", result);
    }

    [Fact]
    public void BuildPasswordChangeUrl_ReturnsCorrectUrl()
    {
        var service = new UrlBuilderService(_loggerMock.Object, _httpContextAccessorMock.Object);

        var request = new PasswordChangeRequest
        {
            Scheme = "https",
            Host = new HostString("example.com"),
            UserId = "u456",
            Token = "xyz"
        };

        var result = service.BuildPasswordChangeUrl(request);

        Assert.Contains("userId=u456", result);
        Assert.Contains("token=xyz", result);
    }

    [Fact]
    public void BuildUrl_ThrowsException_WhenSchemeIsMissing()
    {
        var service = new UrlBuilderService(_loggerMock.Object, _httpContextAccessorMock.Object);

        var request = new PasswordChangeRequest
        {
            Scheme = "",
            Host = new HostString("example.com"),
            UserId = "u1",
            Token = "t1"
        };

        Assert.Throws<ArgumentException>(() => service.BuildPasswordChangeUrl(request));
    }

    [Fact]
    public void BuildUrl_ThrowsException_WhenHostIsMissing()
    {
        var service = new UrlBuilderService(_loggerMock.Object, _httpContextAccessorMock.Object);

        var request = new PasswordChangeRequest
        {
            Scheme = "https",
            Host = new HostString(null!),
            UserId = "u1",
            Token = "t1"
        };

        Assert.Throws<ArgumentException>(() => service.BuildPasswordChangeUrl(request));
    }

    [Fact]
    public void BuildUrl_ThrowsException_WhenRequiredFieldIsMissing()
    {
        var service = new UrlBuilderService(_loggerMock.Object, _httpContextAccessorMock.Object);

        var request = new PasswordChangeRequest
        {
            Scheme = "https",
            Host = new HostString("example.com"),
            UserId = "",
            Token = "token"
        };

        Assert.Throws<ArgumentException>(() => service.BuildPasswordChangeUrl(request));
    }
}
