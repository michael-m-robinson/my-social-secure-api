using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Services.GeoLocation;
using My_Social_Secure_Api.Interfaces.Services.GeoLocation;

public class MaxMindGeolocationServiceTests
{
    [Fact]
    public async Task GetLocationAsync_ReturnsFormattedLocation_WhenSuccessful()
    {
        var mockLogger = new Mock<ILogger<MaxMindGeolocationService>>();
        var mockAccessor = new Mock<IHttpContextAccessor>();
        mockAccessor.Setup(x => x.HttpContext).Returns(new DefaultHttpContext());

        var mockCityResponse = new Mock<ICityResponseWrapper>();
        mockCityResponse.Setup(x => x.GetCityName()).Returns("New York");
        mockCityResponse.Setup(x => x.GetCountryName()).Returns("USA");

        var mockReader = new Mock<IDatabaseReaderWrapper>();
        mockReader.Setup(x => x.City("1.2.3.4")).Returns(mockCityResponse.Object);

        var service = new MaxMindGeolocationService(mockLogger.Object, mockAccessor.Object, mockReader.Object);

        var result = await service.GetLocationAsync("1.2.3.4");

        Assert.Equal("New York, USA", result);
    }

    [Fact]
    public async Task GetLocationAsync_ReturnsUnknown_OnException()
    {
        var mockLogger = new Mock<ILogger<MaxMindGeolocationService>>();
        var mockAccessor = new Mock<IHttpContextAccessor>();
        mockAccessor.Setup(x => x.HttpContext).Returns(new DefaultHttpContext());

        var mockReader = new Mock<IDatabaseReaderWrapper>();
        mockReader.Setup(x => x.City(It.IsAny<string>())).Throws(new Exception("Database error"));

        var service = new MaxMindGeolocationService(mockLogger.Object, mockAccessor.Object, mockReader.Object);

        var result = await service.GetLocationAsync("invalid-ip");

        Assert.Equal("Unknown", result);
    }
}