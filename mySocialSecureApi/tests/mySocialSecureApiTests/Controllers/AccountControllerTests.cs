using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Xunit;
using My_Social_Secure_Api.Controllers;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Account;
using My_Social_Secure_Api.Enums.Common;

namespace mySocialSecureApiTests.Controllers;

public class AccountControllerTests
{
    private readonly Mock<IAccountService> _mockAccountService;
    private readonly AccountController _controller;

    public AccountControllerTests()
    {
        _mockAccountService = new Mock<IAccountService>();
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();

        var httpContext = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation-id"
            }
        };

        mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        _controller = new AccountController(_mockAccountService.Object, mockHttpContextAccessor.Object)
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
    public async Task GetProfile_ReturnsOk_WhenProfileExists()
    {
        // Arrange
        var userId = _controller.User.FindFirstValue(ClaimTypes.NameIdentifier)!;

        var profile = new UserProfileDto
        {
            FirstName = "Jane",
            LastName = "Doe",
            Email = "jane@example.com",
            Status = OperationStatus.Ok
        };

        var response = new ApiResponse<UserProfileDto>
        {
            Success = true,
            Data = profile,
            Message = "Success"
        };

        _mockAccountService
            .Setup(s => s.GetUserProfileAsync(userId))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.GetProfile();

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var responseBody = Assert.IsType<ApiResponse<UserProfileDto>>(ok.Value);
        Assert.True(responseBody.Success);
        Assert.Equal("Jane", responseBody.Data?.FirstName);
    }

    [Fact]
    public async Task GetProfile_ReturnsNotFound_WhenProfileDoesNotExist()
    {
        // Arrange
        var userId = _controller.User.FindFirstValue(ClaimTypes.NameIdentifier)!;

        var response = new ApiResponse<UserProfileDto>
        {
            Success = false,
            Data = null,
            Message = "Not found"
        };

        _mockAccountService
            .Setup(s => s.GetUserProfileAsync(userId))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.GetProfile();

        // Assert
        var notFound = Assert.IsType<NotFoundObjectResult>(result);
        var responseBody = Assert.IsType<ApiResponse<UserProfileDto>>(notFound.Value);
        Assert.False(responseBody.Success);
    }

    [Fact]
    public async Task GetProfile_HandlesException_AndReturnsErrorResponse()
    {
        // Arrange
        var userId = _controller.User.FindFirstValue(ClaimTypes.NameIdentifier)!;

        _mockAccountService
            .Setup(s => s.GetUserProfileAsync(userId))
            .ThrowsAsync(new InvalidOperationException("Failed"));

        // Act
        var result = await _controller.GetProfile();

        // Assert
        var errorResult = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, errorResult.StatusCode);
    }

    [Fact]
    public async Task UpdateProfile_ReturnsOk_WhenUpdateIsSuccessful()
    {
        // Arrange
        var userId = _controller.User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var model = new UpdateProfileRequestDto
        {
            UserId = userId,
            FirstName = "John",
            LastName = "Smith",
            Email = "john@example.com",
            City = "New York",
            State = "NY",
            Status = OperationStatus.Ok
        };

        var response = new ApiResponse<UpdateProfileDto>
        {
            Success = true,
            Data = new UpdateProfileDto
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
                Email = model.Email,
                Status = OperationStatus.Ok
            }
        };

        _mockAccountService
            .Setup(s => s.UpdateProfileAsync(model))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.UpdateProfile(model);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var responseBody = Assert.IsType<ApiResponse<UpdateProfileDto>>(ok.Value);
        Assert.True(responseBody.Success);
        Assert.Equal("john@example.com", responseBody.Data?.Email);
    }

    [Fact]
    public async Task UpdateProfile_ReturnsBadRequest_WhenUpdateFails()
    {
        // Arrange
        var userId = _controller.User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var model = new UpdateProfileRequestDto
        {
            UserId = userId,
            FirstName = "Bad",
            LastName = "Data",
            Email = "bad@example.com",
            Status = OperationStatus.Ok,
            City = "New York",
            State = "NY"
        };

        var response = new ApiResponse<UpdateProfileDto>
        {
            Success = false,
            Message = "Validation failed",
            Data = null
        };

        _mockAccountService
            .Setup(s => s.UpdateProfileAsync(model))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.UpdateProfile(model);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        var responseBody = Assert.IsType<ApiResponse<UpdateProfileDto>>(badRequest.Value);
        Assert.False(responseBody.Success);
    }

    [Fact]
    public async Task UpdateProfile_HandlesException_AndReturnsServerError()
    {
        // Arrange
        var userId = _controller.User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var model = new UpdateProfileRequestDto
        {
            UserId = userId,
            FirstName = "John",
            LastName = "Smith",
            Email = "john@example.com",
            City = "New York",
            State = "NY",
            Status = OperationStatus.Ok
        };

        _mockAccountService
            .Setup(s => s.UpdateProfileAsync(model))
            .ThrowsAsync(new Exception("Unexpected error"));

        // Act
        var result = await _controller.UpdateProfile(model);

        // Assert
        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, error.StatusCode);
    }
    
}