using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Xunit;
using My_Social_Secure_Api.Controllers;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Auth;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.Registration;
using My_Social_Secure_Api.Models.Dtos.Security;

namespace mySocialSecureApiTests.Controllers;

public class AuthControllerTests
{
    private readonly Mock<IAuthService> _mockAuthService;
    private readonly Mock<IRefreshTokenService> _mockRefreshTokenService;
    private readonly Mock<IHttpContextAccessor> _mockHttpContextAccessor;
    private readonly AuthController _controller;

    public AuthControllerTests()
    {
        _mockAuthService = new Mock<IAuthService>();
        _mockRefreshTokenService = new Mock<IRefreshTokenService>();
        _mockHttpContextAccessor = new Mock<IHttpContextAccessor>();

        var httpContext = new DefaultHttpContext
        {
            Items =
            {
                ["X-Correlation-ID"] = "test-correlation-id"
            }
        };

        _mockHttpContextAccessor.Setup(a => a.HttpContext).Returns(httpContext);

        _controller = new AuthController(
            _mockAuthService.Object,
            _mockRefreshTokenService.Object,
            _mockHttpContextAccessor.Object
        )
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            }
        };
    }

    [Fact]
    public async Task Register_ReturnsOk_WhenSuccessful()
    {
        // Arrange
        var dto = new RegisterRequestDto
        {
            Email = "user@example.com",
            Password = "Password123!",
            FirstName = "John",
            LastName = "Doe"
        };

        var response = new ApiResponse<RegisterDto>
        {
            Success = true,
            Message = "User registered successfully",
            Data = new RegisterDto
            {
                Id = Guid.NewGuid(),
                BenefitType = "Standard",
                City = "New York",
                State = "NY",
                CreatedAt = DateTime.UtcNow,
                EarningsLastFiveYears = 5000,
                Description = "New user",
                Email = "test@testuser.com",
                EmailConfirmationSent = true,
                Status = OperationStatus.Ok
            }
        };

        _mockAuthService
            .Setup(s => s.RegisterNewUserAsync(dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.Register(dto);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<RegisterDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.NotNull(body.Data?.Id);
    }

    [Fact]
    public async Task Register_ReturnsBadRequest_WhenRegistrationFails()
    {
        // Arrange
        var dto = new RegisterRequestDto
        {
            Email = "invalid@example.com",
            Password = "short",
            FirstName = "Bad",
            LastName = "Input"
        };

        var response = new ApiResponse<RegisterDto>
        {
            Success = false,
            Message = "Validation failed",
            Data = null
        };

        _mockAuthService
            .Setup(s => s.RegisterNewUserAsync(dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.Register(dto);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        var body = Assert.IsType<ApiResponse<RegisterDto>>(badRequest.Value);
        Assert.False(body.Success);
        Assert.Null(body.Data);
    }

    [Fact]
    public async Task Login_ReturnsOk_WhenLoginIsSuccessful()
    {
        // Arrange
        var dto = new LoginRequestDto
        {
            UserName = "test-user",
            Password = "SecurePass123!",
            RememberMe = true
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = true,
            Data = new OperationDto
            {
                Token = "mock-access-token",
                Status = OperationStatus.Ok
            },
            Message = "Login successful"
        };

        _mockAuthService
            .Setup(s => s.LoginUserAsync(dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.Login(dto);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Equal("mock-access-token", body.Data!.Token);
    }

    [Fact]
    public async Task Login_ReturnsUnauthorized_WhenLoginFails()
    {
        // Arrange
        var dto = new LoginRequestDto
        {
            UserName = "wrong-user",
            Password = "WrongPassword!",
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = false,
            Message = "Invalid credentials",
            Data = null
        };

        _mockAuthService
            .Setup(s => s.LoginUserAsync(dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.Login(dto);

        // Assert
        var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(unauthorized.Value);
        Assert.False(body.Success);
        Assert.Null(body.Data);
    }

    [Fact]
    public async Task LoginWith2Fa_ReturnsOk_WhenSuccessful()
    {
        // Arrange
        var dto = new VerifyTwoFactorDto
        {
            UserName = "user@example.com",
            Code = "123456"
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = true,
            Message = "2FA login successful",
            Data = new OperationDto
            {
                Token = "mock-access-token",
                Status = OperationStatus.Ok,
            }
        };

        _mockAuthService
            .Setup(s => s.LoginUserWith2FaAsync(dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.LoginWith2Fa(dto);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Equal("mock-access-token", body.Data!.Token);
    }

    [Fact]
    public async Task LoginWith2Fa_ReturnsUnauthorized_WhenFails()
    {
        // Arrange
        var dto = new VerifyTwoFactorDto
        {
            UserName = "test-user",
            Code = "000000"
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = false,
            Message = "Invalid 2FA code",
            Data = null
        };

        _mockAuthService
            .Setup(s => s.LoginUserWith2FaAsync(dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.LoginWith2Fa(dto);

        // Assert
        var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(unauthorized.Value);
        Assert.False(body.Success);
        Assert.Null(body.Data);
    }

    [Fact]
    public async Task Logout_ReturnsOk_WhenSuccessful()
    {
        // Arrange
        var dto = new LogoutRequestDto
        {
            UserId = Guid.NewGuid().ToString(),
            Token = "valid-refresh-token"
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = true,
            Message = "Logout successful"
        };

        _mockAuthService
            .Setup(s => s.LogoutUserAsync(dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.Logout(dto);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Equal("Logout successful", body.Message);
    }

    [Fact]
    public async Task Logout_ReturnsBadRequest_WhenLogoutFails()
    {
        // Arrange
        var dto = new LogoutRequestDto
        {
            UserId = Guid.NewGuid().ToString(),
            Token = "invalid-token"
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = false,
            Message = "Logout failed"
        };

        _mockAuthService
            .Setup(s => s.LogoutUserAsync(dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.Logout(dto);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(badRequest.Value);
        Assert.False(body.Success);
        Assert.Equal("Logout failed", body.Message);
    }

    [Fact]
    public async Task Logout_ReturnsServerError_OnException()
    {
        // Arrange
        var dto = new LogoutRequestDto
        {
            UserId = Guid.NewGuid().ToString(),
            Token = "cause-error"
        };

        _mockAuthService
            .Setup(s => s.LogoutUserAsync(dto))
            .ThrowsAsync(new Exception("Unexpected"));

        // Act
        var result = await _controller.Logout(dto);

        // Assert
        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, error.StatusCode);
    }

    [Fact]
    public async Task ResendEmailConfirmation_ReturnsOk_WhenSuccessful()
    {
        // Arrange
        var dto = new ResendRegistrationEmailConfirmationDto
        {
            Email = "user@example.com"
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = true,
            Message = "Confirmation email resent"
        };

        _mockAuthService
            .Setup(s => s.ResendRegistrationEmailConfirmation(dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.ResendEmailConfirmation(dto);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Equal("Confirmation email resent", body.Message);
    }

    [Fact]
    public async Task ResendEmailConfirmation_ReturnsBadRequest_WhenFails()
    {
        // Arrange
        var dto = new ResendRegistrationEmailConfirmationDto
        {
            Email = "invalid@example.com"
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = false,
            Message = "Email not found"
        };

        _mockAuthService
            .Setup(s => s.ResendRegistrationEmailConfirmation(dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.ResendEmailConfirmation(dto);

        // Assert
        var bad = Assert.IsType<BadRequestObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(bad.Value);
        Assert.False(body.Success);
        Assert.Equal("Email not found", body.Message);
    }

    [Fact]
    public async Task ConfirmEmail_ReturnsOk_WhenSuccessful()
    {
        // Arrange
        var dto = new RegistrationEmailConfirmationDto
        {
            UserId = Guid.NewGuid().ToString(),
            Token = "valid-token"
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = true,
            Message = "Email confirmed"
        };

        _mockAuthService
            .Setup(s => s.VerifyAndConfirmRegistrationEmail(dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.ConfirmEmail(dto);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Equal("Email confirmed", body.Message);
    }

    [Fact]
    public async Task ConfirmEmail_ReturnsBadRequest_WhenConfirmationFails()
    {
        // Arrange
        var dto = new RegistrationEmailConfirmationDto
        {
            UserId = Guid.NewGuid().ToString(),
            Token = "invalid-token"
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = false,
            Message = "Invalid token"
        };

        _mockAuthService
            .Setup(s => s.VerifyAndConfirmRegistrationEmail(dto))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.ConfirmEmail(dto);

        // Assert
        var badRequest = Assert.IsType<BadRequestObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(badRequest.Value);
        Assert.False(body.Success);
        Assert.Equal("Invalid token", body.Message);
    }

    [Fact]
    public async Task Refresh_ReturnsOk_WhenTokenIsValid()
    {
        // Arrange
        var dto = new RefreshTokenRequestDto
        {
            RefreshToken = "valid-refresh-token"
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = true,
            Message = "Token refreshed",
            Data = new OperationDto
            {
                Token = "new-access-token",
                Description = "New token",
                Status = OperationStatus.Ok
            }
        };

        _mockRefreshTokenService
            .Setup(s => s.ValidateRefreshTokenAsync(dto.RefreshToken))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.Refresh(dto);

        // Assert
        var ok = Assert.IsType<OkObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(ok.Value);
        Assert.True(body.Success);
        Assert.Equal("new-access-token", body.Data!.Token);
    }

    [Fact]
    public async Task Refresh_ReturnsUnauthorized_WhenTokenIsInvalid()
    {
        // Arrange
        var dto = new RefreshTokenRequestDto
        {
            RefreshToken = "invalid-token"
        };

        var response = new ApiResponse<OperationDto>
        {
            Success = false,
            Message = "Invalid token",
            Data = null
        };

        _mockRefreshTokenService
            .Setup(s => s.ValidateRefreshTokenAsync(dto.RefreshToken))
            .ReturnsAsync(response);

        // Act
        var result = await _controller.Refresh(dto);

        // Assert
        var unauthorized = Assert.IsType<UnauthorizedObjectResult>(result);
        var body = Assert.IsType<ApiResponse<OperationDto>>(unauthorized.Value);
        Assert.False(body.Success);
        Assert.Equal("Invalid token", body.Message);
    }

    [Fact]
    public async Task Refresh_ReturnsServerError_OnException()
    {
        // Arrange
        var dto = new RefreshTokenRequestDto
        {
            RefreshToken = "crash-token"
        };

        _mockRefreshTokenService
            .Setup(s => s.ValidateRefreshTokenAsync(dto.RefreshToken))
            .ThrowsAsync(new Exception("Unexpected error"));

        // Act
        var result = await _controller.Refresh(dto);

        // Assert
        var error = Assert.IsType<ObjectResult>(result);
        Assert.Equal(StatusCodes.Status500InternalServerError, error.StatusCode);
    }
    
    
}