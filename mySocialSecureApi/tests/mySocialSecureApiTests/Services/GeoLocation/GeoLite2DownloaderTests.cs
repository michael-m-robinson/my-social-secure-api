using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using Xunit;
using My_Social_Secure_Api.Services.GeoLocation;

public class GeoLite2DownloaderTests
{
    [Fact]
    public async Task DownloadAndExtractAsync_ThrowsOnHttpFailure()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<GeoLite2Downloader>>();
        var mockHttpContext = new Mock<IHttpContextAccessor>();
        mockHttpContext.Setup(x => x.HttpContext).Returns(new DefaultHttpContext());

        var handler = new Mock<HttpMessageHandler>();
        var client = new HttpClient(handler.Object);

        var response = new HttpResponseMessage(HttpStatusCode.NotFound);
        handler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(response);

        var service = new GeoLite2Downloader(mockLogger.Object, mockHttpContext.Object, client);

        // Act & Assert
        var ex = await Assert.ThrowsAsync<HttpRequestException>(() =>
            service.DownloadAndExtractAsync("fake-license-key", "output.mmdb")
        );

        Assert.NotNull(ex);
    }

    [Fact]
    public void BuildDownloadUrl_ReturnsValidUrl()
    {
        var mockLogger = new Mock<ILogger<GeoLite2Downloader>>();
        var mockHttpContext = new Mock<IHttpContextAccessor>();
        mockHttpContext.Setup(x => x.HttpContext).Returns(new DefaultHttpContext());
        var client = new HttpClient();

        var service = new GeoLite2Downloader(mockLogger.Object, mockHttpContext.Object, client);

        var result = typeof(GeoLite2Downloader)
            .GetMethod("BuildDownloadUrl", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
            ?.Invoke(service, ["abc123"]) as string;

        Assert.Contains("abc123", result);
        Assert.StartsWith("https://download.maxmind.com", result);
    }
}
