using System.Text.Json;
using My_Social_Secure_Api.Services.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace My_Social_Secure_Api_Tests.Services.RateLimiting;

public class RateLimitResponseWriterTests
{
    [Fact]
    public async Task WriteAsync_Sets429StatusAndReturnsExpectedJson()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var stream = new MemoryStream();
        context.Response.Body = stream;
        
        var mockLogger = new Mock<ILogger<RateLimitResponseWriter>>();
        var serviceProvider = new Mock<IServiceProvider>();
        serviceProvider
            .Setup(sp => sp.GetService(typeof(ILogger<RateLimitResponseWriter>)))
            .Returns(mockLogger.Object);

        context.RequestServices = serviceProvider.Object;

        var writer = new RateLimitResponseWriter();
        var message = "Too many requests";
        var token = CancellationToken.None;

        // Act
        await writer.WriteAsync(context, message, token);
        stream.Seek(0, SeekOrigin.Begin);

        var json = await JsonSerializer.DeserializeAsync<JsonElement>(stream, cancellationToken: token);

        // Assert
        Assert.Equal(StatusCodes.Status429TooManyRequests, context.Response.StatusCode);
        Assert.Equal("application/json; charset=utf-8", context.Response.ContentType);
        Assert.Equal(message, json.GetProperty("message").GetString());
        Assert.True(DateTime.TryParse(json.GetProperty("timestamp").GetString(), out _));
    }

}