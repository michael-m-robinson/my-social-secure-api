using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using Xunit;
using My_Social_Secure_Api.Services.Security;

public class PwnedPasswordServiceTests
{
    [Fact]
    public async Task IsPasswordPwnedAsync_ReturnsTrue_WhenPasswordIsFound()
    {
        var sha1 = System.Security.Cryptography.SHA1.Create();
        var password = "password";
        var hash = sha1.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        var hashString = BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        var suffix = hashString[5..].ToUpper();

        var responseMessage = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{suffix}:5\n")
        };

        var handler = new Mock<HttpMessageHandler>();
        handler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(responseMessage);

        var httpClient = new HttpClient(handler.Object);
        var logger = new Mock<ILogger<PwnedPasswordService>>();
        var context = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test"
            }
        };
        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(x => x.HttpContext).Returns(context);

        var service = new PwnedPasswordService(httpClient, logger.Object, accessor.Object);
        var result = await service.IsPasswordPwnedAsync(password);

        Assert.True(result);
    }

    [Fact]
    public async Task IsPasswordPwnedAsync_ReturnsFalse_WhenPasswordIsNotFound()
    {
        var password = "unique-password123!@#";
        var responseMessage = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("ABC123:2\nDEF456:1")
        };

        var handler = new Mock<HttpMessageHandler>();
        handler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(responseMessage);

        var httpClient = new HttpClient(handler.Object);
        var logger = new Mock<ILogger<PwnedPasswordService>>();
        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(x => x.HttpContext).Returns(new DefaultHttpContext());

        var service = new PwnedPasswordService(httpClient, logger.Object, accessor.Object);
        var result = await service.IsPasswordPwnedAsync(password);

        Assert.False(result);
    }

    [Fact]
    public async Task IsPasswordPwnedAsync_Throws_WhenApiFails()
    {
        var handler = new Mock<HttpMessageHandler>();
        handler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .Throws(new HttpRequestException("API is down"));

        var httpClient = new HttpClient(handler.Object);
        var logger = new Mock<ILogger<PwnedPasswordService>>();
        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(x => x.HttpContext).Returns(new DefaultHttpContext());

        var service = new PwnedPasswordService(httpClient, logger.Object, accessor.Object);

        await Assert.ThrowsAsync<HttpRequestException>(() => service.IsPasswordPwnedAsync("password"));
    }

    [Fact]
    public async Task IsPasswordPwnedAsync_Throws_WhenPasswordIsInvalid()
    {
        var client = new HttpClient();
        var logger = new Mock<ILogger<PwnedPasswordService>>();
        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(x => x.HttpContext).Returns(new DefaultHttpContext());

        var service = new PwnedPasswordService(client, logger.Object, accessor.Object);

        await Assert.ThrowsAsync<ArgumentException>(() => service.IsPasswordPwnedAsync("   "));
    }
}