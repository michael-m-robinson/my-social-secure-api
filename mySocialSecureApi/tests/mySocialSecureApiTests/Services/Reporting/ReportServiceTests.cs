using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Services.Reporting;
using My_Social_Secure_Api.Models.Dtos.Reporting;
using My_Social_Secure_Api.Models.Entities.Feedback;
using My_Social_Secure_Api.Models.Identity;

public class ReportServiceTests
{
    private readonly ApplicationDbContext _dbContext;
    private readonly Mock<ILogger<ReportService>> _mockLogger;
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;

    public ReportServiceTests()
    {
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _dbContext = new ApplicationDbContext(options);
        _mockLogger = new Mock<ILogger<ReportService>>();
        _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();

        var httpContext = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation-id"
            }
        };
        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);
    }

    [Fact]
    public async Task GetAppUsageReportAsync_ReturnsSuccessResponse()
    {
        // Arrange
        var options = new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        var context = new ApplicationDbContext(options);
        
        // Seed users and feedback
        var userOneId = Guid.NewGuid().ToString();
        var userTwoId = Guid.NewGuid().ToString();
        
        context.Users.AddRange(
            new ApplicationUser
            {
                Id = userOneId,
                UserName = "user1",
                Email = "user1@example.com",
                FirstName = "User",
                LastName = "One",
                City = "City1",
                State = "State1",
            },
            new ApplicationUser
            {
                Id = userTwoId,
                UserName = "user2",
                Email = "user2@example.com",
                FirstName = "User",
                LastName = "Two",
                City = "City2",
                State = "State2",
            }
        );
        context.Feedbacks.AddRange(
            new FeedbackModel { Id = Guid.NewGuid(), UserId = userOneId, Feedback = "Good job" },
            new FeedbackModel { Id = Guid.NewGuid(), UserId = userTwoId, Feedback = "Needs improvement" },
            new FeedbackModel { Id = Guid.NewGuid(), UserId = userOneId, Feedback = "Awesome!" }
        );
        await context.SaveChangesAsync();
        
        var mockLogger = new Mock<ILogger<ReportService>>();
        var mockAccessor = new Mock<IHttpContextAccessor>();
        mockAccessor.Setup(x => x.HttpContext).Returns(new DefaultHttpContext());

        var service = new ReportService(context, mockLogger.Object, mockAccessor.Object);

        // Act
        var result = await service.GetAppUsageReportAsync();

        // Assert
        Assert.True(result.Success);
        Assert.Equal("App usage report", result.Message);
        Assert.NotNull(result.Data);
        Assert.Equal(2, result.Data.TotalUsers);
        Assert.Equal(3, result.Data.TotalFeedback);
    }
    
    private TestableReportService CreateService(UsageReportDto usage)
    {
        return new TestableReportService(
            _dbContext,
            _mockLogger.Object,
            _mockHttpContextAccessor.Object,
            usage
        );
    }
}

internal class TestableReportService(
    ApplicationDbContext context,
    ILogger<ReportService> logger,
    IHttpContextAccessor accessor,
    UsageReportDto mockUsageReport)
    : ReportService(context, logger, accessor)
{
    protected Task<UsageReportDto> BuildUsageReportAsync()
    {
        return Task.FromResult(mockUsageReport);
    }
}
