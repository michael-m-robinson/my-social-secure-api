using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using My_Social_Secure_Api_Tests.Utilities;
using My_Social_Secure_Api.Interfaces.Services.GeoLocation;
using My_Social_Secure_Api.Services.GeoLocation;
using Xunit;

public class GeoLite2UpdateServiceTests
{
    public GeoLite2UpdateServiceTests()
    {
        TestEnvLoader.Load();
    }

    
    [Fact]
    public async Task ExecuteAsync_TriggersDatabaseUpdate()
    {
        // Arrange
        var mockLogger = new Mock<ILogger<GeoLite2UpdateService>>();
        var mockAccessor = new Mock<IHttpContextAccessor>();
        var mockDownloader = new Mock<IGeoLite2Downloader>();
        var mockEnv = new Mock<IWebHostEnvironment>();
        mockEnv.Setup(e => e.ContentRootPath).Returns("/tmp/test-root");
        mockAccessor.Setup(x => x.HttpContext).Returns(new DefaultHttpContext());

        var cts = new CancellationTokenSource();
        cts.CancelAfter(100); // cancel quickly for the test

        var service = new TestableGeoLite2UpdateService(mockLogger.Object, mockAccessor.Object, mockEnv.Object, mockDownloader.Object);

        // Act
        await service.StartAsync(cts.Token);

        // Assert
        mockDownloader.Verify(x => x.DownloadAndExtractAsync(
                It.IsAny<string>(), It.Is<string>(s => s.EndsWith("GeoLite2-City.mmdb"))),
            Times.AtLeastOnce);
    }

    private class TestableGeoLite2UpdateService(
        ILogger<GeoLite2UpdateService> logger,
        IHttpContextAccessor accessor,
        IWebHostEnvironment env,
        IGeoLite2Downloader downloader)
        : GeoLite2UpdateService(logger, accessor, env, downloader);
}