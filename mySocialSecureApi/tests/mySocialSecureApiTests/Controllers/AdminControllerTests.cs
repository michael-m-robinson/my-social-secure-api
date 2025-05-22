using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using My_Social_Secure_Api.Controllers;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Admin;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Admin;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.LoginTracking;
using My_Social_Secure_Api.Models.Dtos.Notifications;

namespace mySocialSecureApiTests.Controllers;

public class AdminControllerTests
{
    private readonly Mock<IAdminService> _mockAdminService;
    private readonly AdminController _controller;

    public AdminControllerTests()
    {
        _mockAdminService = new Mock<IAdminService>();
        var mockLogger = new Mock<ILogger<AdminController>>();
        var mockHttpContextAccessor = new Mock<IHttpContextAccessor>();

        var httpContext = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation-id"
            }
        };

        mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        _controller = new AdminController(
            _mockAdminService.Object,
            mockLogger.Object,
            mockHttpContextAccessor.Object
        )
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
    public async Task GetAllUsers_ReturnsOk_WhenSuccessful()
    {
        // Arrange
        var response = new ApiResponse<UserListDto>
        {
            Success = true,
            Data = new UserListDto
            {
                Status = OperationStatus.Ok,
                Users =
                [
                    new UserDto
                    {
                        Status = OperationStatus.Ok,
                        Id = Guid.NewGuid().ToString(),
                        Email = "test@test.com",
                        FirstName = "Test",
                        UserName = "TestUser",
                    }
                ]
            }
        };

        _mockAdminService
            .Setup(s => s.GetAllUsersAsync())
            .ReturnsAsync(response);

        // Act
        var result = await _controller.GetAllUsers();

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<UserListDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Single(body.Data!.Users);
    }

    [Fact]
    public async Task GetAllUsers_ReturnsBadRequest_WhenServiceFails()
    {
        // Arrange
        var response = new ApiResponse<UserListDto>
        {
            Success = false,
            Message = "Could not retrieve users",
            Data = null
        };

        _mockAdminService
            .Setup(s => s.GetAllUsersAsync())
            .ReturnsAsync(response);

        // Act
        var result = await _controller.GetAllUsers();

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        var body = Assert.IsType<ApiResponse<UserListDto>>(badRequest.Value);
        Assert.False(body.Success);
    }

    [Fact]
    public async Task GetAllUsers_ReturnsServerError_OnException()
    {
        // Arrange
        _mockAdminService
            .Setup(s => s.GetAllUsersAsync())
            .ThrowsAsync(new Exception("Unhandled failure"));

        // Act
        var result = await _controller.GetAllUsers();

        // Assert
        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, error.StatusCode);
    }

    [Fact]
    public async Task GetUserById_ReturnsOk_WhenUserExists()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var user = new UserActionDto
        {
            UserId = userId,
            UserName = "TestUser",
            Email = "test@example.com",
            Status = OperationStatus.Ok
        };

        var response = new ApiResponse<UserActionDto>
        {
            Success = true,
            Data = user
        };

        _mockAdminService
            .Setup(s => s.GetUserByIdAsync(userId))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.GetUserById(userId);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<UserActionDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Equal("test@example.com", body.Data?.Email);
    }

    [Fact]
    public async Task GetUserById_ReturnsNotFound_WhenUserNotFound()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var response = new ApiResponse<UserActionDto>
        {
            Success = false,
            Message = "User not found",
            Data = null
        };

        _mockAdminService
            .Setup(s => s.GetUserByIdAsync(userId))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.GetUserById(userId);

        // Assert
        var notFound = Assert.IsType<NotFoundObjectResult>(result);
        var body = Assert.IsType<ApiResponse<UserActionDto>>(notFound.Value);
        Assert.False(body.Success);
    }

    [Fact]
    public async Task GetUserById_ReturnsServerError_OnException()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();

        _mockAdminService
            .Setup(s => s.GetUserByIdAsync(userId))
            .ThrowsAsync(new Exception("Database error"));

        // Act
        var result = await _controller.GetUserById(userId);

        // Assert
        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, error.StatusCode);
    }

    [Fact]
    public async Task UpdateUser_ReturnsOk_WhenUpdateIsSuccessful()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var dto = new UpdateUserDto
        {
            FirstName = "Updated",
            LastName = "User",
            UserName = "UpdatedUser",
            Email = "updated@example.com",
        };

        var response = new ApiResponse<UserActionDto>
        {
            Success = true,
            Data = new UserActionDto
            {
                UserId = userId,
                Email = dto.Email,
                UserName = "UpdatedUser",
                Status = OperationStatus.Ok
            }
        };

        _mockAdminService
            .Setup(s => s.UpdateUserAsync(userId, dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.UpdateUser(userId, dto);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<UserActionDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Equal("updated@example.com", body.Data?.Email);
    }

    [Fact]
    public async Task UpdateUser_ReturnsBadRequest_WhenUpdateFails()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var dto = new UpdateUserDto
        {
            FirstName = "Invalid",
            LastName = "User",
            UserName = "InvalidUser",
            Email = "invalid@example.com"
        };

        var response = new ApiResponse<UserActionDto>
        {
            Success = false,
            Message = "Validation error",
            Data = null
        };

        _mockAdminService
            .Setup(s => s.UpdateUserAsync(userId, dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.UpdateUser(userId, dto);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        var body = Assert.IsType<ApiResponse<UserActionDto>>(badRequest.Value);
        Assert.False(body.Success);
    }

    [Fact]
    public async Task UpdateUser_ReturnsServerError_OnException()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var dto = new UpdateUserDto
        {
            FirstName = "Error",
            LastName = "Case",
            Email = "error@example.com"
        };

        _mockAdminService
            .Setup(s => s.UpdateUserAsync(userId, dto))
            .ThrowsAsync(new Exception("Unexpected"));

        // Act
        var result = await _controller.UpdateUser(userId, dto);

        // Assert
        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, error.StatusCode);
    }

    [Fact]
    public async Task AssignRole_ReturnsOk_WhenSuccessful()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var role = "Moderator";

        var response = new ApiResponse<OperationDto>
        {
            Success = true,
            Message = "Role assigned"
        };
        
        _mockAdminService
            .Setup(s => s.AssignRoleAsync(It.IsAny<RoleAssignmentRequestDto>()))
            .ReturnsAsync(response);
        
        // Act
        var result = await _controller.AssignRole(userId, role);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Equal("Role assigned", body.Message);
    }

    [Fact]
    public async Task AssignRole_ReturnsBadRequest_WhenAssignmentFails()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var role = "InvalidRole";

        var response = new ApiResponse<OperationDto>
        {
            Success = false,
            Message = "Role does not exist"
        };

        _mockAdminService
            .Setup(s => s.AssignRoleAsync(It.IsAny<RoleAssignmentRequestDto>()))
            .ReturnsAsync(response);


        // Act
        var result = await _controller.AssignRole(userId, role);

        // Assert
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(bad.Value);
        Assert.False(body.Success);
        Assert.Equal("Role does not exist", body.Message);
    }

    [Fact]
    public async Task AssignRole_ReturnsServerError_OnException()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var role = "Admin";

        _mockAdminService
            .Setup(s => s.AssignRoleAsync(new RoleAssignmentRequestDto
            {
                UserId = userId,
                RoleName = role
            }))
            .ThrowsAsync(new Exception("Unexpected error"));

        // Act
        var result = await _controller.AssignRole(userId, role);

        // Assert
        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, error.StatusCode);
    }

    [Fact]
    public async Task RemoveRole_ReturnsOk_WhenSuccessful()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var role = "Moderator";

        var response = new ApiResponse<OperationDto>
        {
            Success = true,
            Message = "Role removed"
        };

        _mockAdminService
            .Setup(s => s.RemoveRoleAsync(It.IsAny<RoleRemovalRequestDto>()))
            .ReturnsAsync(response);
        
        // Act
        var result = await _controller.RemoveRole(userId, role);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Equal("Role removed", body.Message);
    }

    [Fact]
    public async Task RemoveRole_ReturnsBadRequest_WhenRemovalFails()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var role = "NonExistentRole";

        var response = new ApiResponse<OperationDto>
        {
            Success = false,
            Message = "Role not assigned"
        };

        _mockAdminService
            .Setup(s => s.RemoveRoleAsync(It.IsAny<RoleRemovalRequestDto>()))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.RemoveRole(userId, role);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(badRequest.Value);
        Assert.False(body.Success);
        Assert.Equal("Role not assigned", body.Message);
    }

    [Fact]
    public async Task RemoveRole_ReturnsServerError_OnException()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var role = "Admin";
        
        var dto = new RoleRemovalRequestDto
        {
            UserId = userId,
            RoleName = role
        };

        _mockAdminService
            .Setup(s => s.RemoveRoleAsync(dto))
            .ThrowsAsync(new Exception("Unexpected"));

        // Act
        var result = await _controller.RemoveRole(userId, role);

        // Assert
        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, error.StatusCode);
    }

    [Fact]
    public async Task GetUserRoles_ReturnsOk_WhenRolesExist()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var response = new ApiResponse<RoleListDto>
        {
            Success = true,
            Data = new RoleListDto
            {
                Roles =
                [
                    "Admin",
                    "Editor"
                ],
                Status = OperationStatus.Ok
            }
        };

        _mockAdminService
            .Setup(s => s.GetUserRolesAsync(userId))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.GetUserRoles(userId);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<RoleListDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Contains("Admin", body.Data!.Roles);
    }

    [Fact]
    public async Task GetUserRoles_ReturnsNotFound_WhenRolesNotFound()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var response = new ApiResponse<RoleListDto>
        {
            Success = false,
            Message = "No roles found",
            Data = null
        };

        _mockAdminService
            .Setup(s => s.GetUserRolesAsync(userId))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.GetUserRoles(userId);

        // Assert
        var notFound = Assert.IsType<NotFoundObjectResult>(result);
        var body = Assert.IsType<ApiResponse<RoleListDto>>(notFound.Value);
        Assert.False(body.Success);
    }

    [Fact]
    public async Task GetUserRoles_ReturnsServerError_OnException()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();

        _mockAdminService
            .Setup(s => s.GetUserRolesAsync(userId))
            .ThrowsAsync(new Exception("Unexpected"));

        // Act
        var result = await _controller.GetUserRoles(userId);

        // Assert
        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, error.StatusCode);
    }

    [Fact]
    public async Task GetUserLoginHistory_ReturnsOk_WhenHistoryExists()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var response = new ApiResponse<LoginHistoryListDto>
        {
            Success = true,
            Data = new LoginHistoryListDto
            {
                LoginHistories =
                [
                    new LoginHistoryDto
                    {
                        Device = "Windows",
                        Location = "New York",
                        IpAddress = "3.3.3.3",
                        LoginTimeUtc = DateTime.UtcNow,
                        Status = OperationStatus.Ok,
                    }
                ],
                Status = OperationStatus.Ok
            }
        };

        _mockAdminService
            .Setup(s => s.GetUserLoginHistoryAsync(userId))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.GetUserLoginHistory(userId);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<LoginHistoryListDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Single(body.Data!.LoginHistories);
    }

    [Fact]
    public async Task GetUserLoginHistory_ReturnsNotFound_WhenNoHistoryExists()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var response = new ApiResponse<LoginHistoryListDto>
        {
            Success = false,
            Message = "No login history found",
            Data = null
        };

        _mockAdminService
            .Setup(s => s.GetUserLoginHistoryAsync(userId))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.GetUserLoginHistory(userId);

        // Assert
        var notFound = Assert.IsType<NotFoundObjectResult>(result);
        var body = Assert.IsType<ApiResponse<LoginHistoryListDto>>(notFound.Value);
        Assert.False(body.Success);
    }

    [Fact]
    public async Task GetUserLoginHistory_ReturnsServerError_OnException()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();

        _mockAdminService
            .Setup(s => s.GetUserLoginHistoryAsync(userId))
            .ThrowsAsync(new Exception("Unexpected failure"));

        // Act
        var result = await _controller.GetUserLoginHistory(userId);

        // Assert
        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, error.StatusCode);
    }

    [Fact]
    public async Task GetTopTenLoginAlerts_ReturnsOk_WhenAlertsExist()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var response = new ApiResponse<LoginAlertListDto>
        {
            Success = true,
            Data = new LoginAlertListDto
            {
                LoginAlerts =
                [
                    new LoginAlertDto
                    {
                        DeviceSummary = "Windows",
                        Location = "New York",
                        IpAddress = "3.3.3.3",
                        LoginTime = "2023-10-01T12:00:00Z"
                    }
                ],
                Status = OperationStatus.Ok
            }
        };

        _mockAdminService
            .Setup(s => s.GetTopTenUserLoginAlertsAsync(userId, 10))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.GetTopTenLoginAlerts(userId);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<LoginAlertListDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Single(body.Data!.LoginAlerts!);
    }

    [Fact]
    public async Task GetTopTenLoginAlerts_ReturnsNotFound_WhenNoAlertsExist()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        var response = new ApiResponse<LoginAlertListDto>
        {
            Success = false,
            Message = "No alerts found",
            Data = null
        };

        _mockAdminService
            .Setup(s => s.GetTopTenUserLoginAlertsAsync(userId, 10))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.GetTopTenLoginAlerts(userId);

        // Assert
        var notFound = Assert.IsType<NotFoundObjectResult>(result);
        var body = Assert.IsType<ApiResponse<LoginAlertListDto>>(notFound.Value);
        Assert.False(body.Success);
    }

    [Fact]
    public async Task GetTopTenLoginAlerts_ReturnsServerError_OnException()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();

        _mockAdminService
            .Setup(s => s.GetTopTenUserLoginAlertsAsync(userId, 10))
            .ThrowsAsync(new Exception("Internal failure"));

        // Act
        var result = await _controller.GetTopTenLoginAlerts(userId);

        // Assert
        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, error.StatusCode);
    }
}