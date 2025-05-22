using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Models.Entities.Feedback;
using My_Social_Secure_Api.Services.Feedback;

public class FeedbackServiceTests
{
    private readonly ApplicationDbContext _dbContext;
    private readonly Mock<ILogger<FeedbackService>> _mockLogger;
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
    private readonly FeedbackService _service;

    public FeedbackServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;

        _dbContext = new ApplicationDbContext(options);
        _mockLogger = new Mock<ILogger<FeedbackService>>();
        _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();

        var httpContext = new DefaultHttpContext
        {
            Connection =
            {
                RemoteIpAddress = IPAddress.Parse("127.0.0.1")
            },
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation-id"
            }
        };
        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        _service = new FeedbackService(_dbContext, _mockLogger.Object, _mockHttpContextAccessor.Object);
    }

    [Fact]
    public async Task GetFeedbackAsync_ReturnsFeedbackList()
    {
        _dbContext.Feedbacks.AddRange(new[]
        {
            new FeedbackModel() { Id = Guid.NewGuid(), UserId = "1", Feedback = "Great app!", CreatedAt = DateTime.UtcNow },
            new FeedbackModel { Id = Guid.NewGuid(), UserId = "2", Feedback = "Could improve UX", CreatedAt = DateTime.UtcNow }
        });
        await _dbContext.SaveChangesAsync();

        var result = await _service.GetFeedbackAsync();

        Assert.True(result.Success);
        Assert.Equal(2, result.Data!.Feedback.Count);
        Assert.All(result.Data.Feedback, f => Assert.Equal("Ok", f.Status.ToString()));
    }

    [Fact]
    public async Task GetFeedbackAsync_ReturnsEmptyList_WhenNoFeedback()
    {
        var result = await _service.GetFeedbackAsync();

        Assert.True(result.Success);
        Assert.Empty(result.Data!.Feedback);
    }
}
