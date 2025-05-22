using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Xunit;
using My_Social_Secure_Api.Controllers;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Feedback;
using My_Social_Secure_Api.Models.Dtos.Feedback;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Common;

namespace mySocialSecureApiTests.Controllers;

public class FeedbackControllerTests
{
    private readonly Mock<IFeedbackService> _mockFeedbackService;
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
    private readonly FeedbackController _controller;

    public FeedbackControllerTests()
    {
        _mockFeedbackService = new Mock<IFeedbackService>();
        _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();

        var httpContext = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation-id"
            }
        };

        _mockHttpContextAccessor.Setup(x => x.HttpContext).Returns(httpContext);

        _controller = new FeedbackController(_mockFeedbackService.Object, _mockHttpContextAccessor.Object)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(new ClaimsIdentity([
                        new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())
                    ]))
                }
            }
        };
    }

    [Fact]
    public async Task GetFeedback_ReturnsOk_WhenServiceReturnsSuccess()
    {
        // Arrange
        var mockData = new FeedbackListDto
        {
            Feedback =
            [
                new()
                {
                    Id = Guid.NewGuid()
                        .ToString(),
                    Feedback = "Great service!",
                    CreatedAt = DateTime.UtcNow,
                    Status = OperationStatus.Ok
                }
            ],
            Status = OperationStatus.Ok
        };

        var response = new ApiResponse<FeedbackListDto>
        {
            Success = true,
            Data = mockData,
            Message = "Fetched successfully"
        };

        _mockFeedbackService.Setup(s => s.GetFeedbackAsync()).ReturnsAsync(response);

        // Act
        var result = await _controller.GetFeedback();

        // Assert
        var okResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status200OK, okResult.StatusCode);
        var responseBody = Assert.IsType<ApiResponse<FeedbackListDto>>(okResult.Value);
        Assert.True(responseBody.Success);
        Assert.NotNull(responseBody.Data);
        Assert.Single(responseBody.Data.Feedback);
    }

    [Fact]
    public async Task GetFeedback_ReturnsInternalServerError_WhenServiceFails()
    {
        // Arrange
        var response = new ApiResponse<FeedbackListDto>
        {
            Success = false,
            Message = "Something went wrong",
            Data = null
        };

        _mockFeedbackService.Setup(s => s.GetFeedbackAsync()).ReturnsAsync(response);

        // Act
        var result = await _controller.GetFeedback();

        // Assert
        var objectResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, objectResult.StatusCode);
        var responseBody = Assert.IsType<ApiResponse<FeedbackListDto>>(objectResult.Value);
        Assert.False(responseBody.Success);
        Assert.Null(responseBody.Data);
    }

    [Fact]
    public async Task GetById_ReturnsOk_WhenFeedbackExists()
    {
        // Arrange
        Guid id = Guid.NewGuid();
        var feedback = new FeedbackDto
        {
            Id = id.ToString(),
            Feedback = "This is valid feedback",
            CreatedAt = DateTime.UtcNow,
            Status = OperationStatus.Ok
        };

        var response = new ApiResponse<FeedbackDto>
        {
            Success = true,
            Data = feedback,
            Message = "Found"
        };

        _mockFeedbackService.Setup(s => s.GetByIdAsync(id)).ReturnsAsync(response);

        // Act
        var result = await _controller.GetById(id);

        // Assert
        var okResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status200OK, okResult.StatusCode);
        var responseBody = Assert.IsType<ApiResponse<FeedbackDto>>(okResult.Value);
        Assert.True(responseBody.Success);
        Assert.Equal(id.ToString(), responseBody.Data?.Id);
    }

    [Fact]
    public async Task GetById_ReturnsNotFound_WhenFeedbackDoesNotExist()
    {
        // Arrange
        var id = Guid.NewGuid();

        var response = new ApiResponse<FeedbackDto>
        {
            Success = false,
            Data = null,
            Message = "Not found"
        };

        _mockFeedbackService.Setup(s => s.GetByIdAsync(id)).ReturnsAsync(response);

        // Act
        var result = await _controller.GetById(id);

        // Assert
        var notFoundResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status404NotFound, notFoundResult.StatusCode);
        var responseBody = Assert.IsType<ApiResponse<FeedbackDto>>(notFoundResult.Value);
        Assert.False(responseBody.Success);
        Assert.Null(responseBody.Data);
    }

    [Fact]
    public async Task Submit_ReturnsOk_WhenSubmissionIsSuccessful()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();

        var model = new CreateFeedbackDto
        {
            Feedback = "Really helpful service"
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = true,
            Message = "Submitted",
            Data = new OperationDto
            {
                Description = $"Feedback : {model.Feedback}",
                Status = OperationStatus.Ok
            }
        };

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId)
        };
        var identity = new ClaimsIdentity(claims, "TestAuthType");
        var claimsPrincipal = new ClaimsPrincipal(identity);
        
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = claimsPrincipal
            }
        };

        _mockFeedbackService
            .Setup(s => s.SubmitAsync(model, userId))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.Submit(model);

        // Assert
        var okResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status200OK, okResult.StatusCode);
        var responseBody = Assert.IsType<ApiResponse<OperationDto>>(okResult.Value);
        Assert.True(responseBody.Success);
        Assert.Equal($"Feedback : {model.Feedback}", responseBody.Data?.Description);
    }

    [Fact]
    public async Task Submit_ReturnsBadRequest_WhenSubmissionFails()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();

        var model = new CreateFeedbackDto
        {
            Feedback = "Invalid data test"
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = false,
            Message = "Validation failed",
            Data = null
        };

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId)
        };
        var identity = new ClaimsIdentity(claims, "TestAuthType");
        var claimsPrincipal = new ClaimsPrincipal(identity);
        
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = claimsPrincipal
            }
        };

       // _mockHttpContextAccessor.Setup(x => x.HttpContext!.User).Returns(claimsPrincipal);

        _mockFeedbackService
            .Setup(s => s.SubmitAsync(model, userId))
            .ReturnsAsync(response);


        // Act
        var result = await _controller.Submit(model);

        // Assert
        var badRequest = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status400BadRequest, badRequest.StatusCode);
        var responseBody = Assert.IsType<ApiResponse<OperationDto>>(badRequest.Value);
        Assert.False(responseBody.Success);
        Assert.Null(responseBody.Data);
    }
}