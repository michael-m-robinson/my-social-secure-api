using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Swashbuckle.AspNetCore.Annotations;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Auth;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.Security;
using My_Social_Secure_Api.Models.Dtos.Registration;

namespace My_Social_Secure_Api.Controllers;

[ApiController]
[Route("[controller]")]
[AllowAnonymous]
public class AuthController(
    IAuthService authService,
    IRefreshTokenService refreshTokenService,
    IHttpContextAccessor accessor) : ControllerBase
{
    private string CorrelationId => accessor.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    [EnableRateLimiting("RegistrationPolicy")]
    [HttpPost("register")]
    [SwaggerOperation(Summary = "Register new user", Description = "Creates a new user account.")]
    [SwaggerResponse(StatusCodes.Status200OK, "User registered successfully.", typeof(ApiResponse<RegisterDto>))]
    public async Task<IActionResult> Register([FromBody] RegisterRequestDto dto)
    {
        dto.Host = accessor.HttpContext?.Request.Host ?? default;
        dto.Scheme = accessor.HttpContext?.Request.Scheme ?? "https";

        var result = await authService.RegisterNewUserAsync(dto);
        Response.Headers.Append("X-Correlation-ID", CorrelationId);
        return result.Success ? Ok(result) : BadRequest(result);
    }

    [EnableRateLimiting("LoginPolicy")]
    [HttpPost("login")]
    [SwaggerOperation(Summary = "Login user", Description = "Logs in a user and returns auth token or initiates 2FA.")]
    [SwaggerResponse(StatusCodes.Status200OK, "User login result", typeof(ApiResponse<OperationDto>))]
    public async Task<IActionResult> Login([FromBody] LoginRequestDto dto)
    {
        dto.Host = accessor.HttpContext?.Request.Host ?? default;
        dto.Scheme = accessor.HttpContext?.Request.Scheme ?? "https";

        var result = await authService.LoginUserAsync(dto);
        Response.Headers.Append("X-Correlation-ID", CorrelationId);
        return result.Success ? Ok(result) : Unauthorized(result);
    }

    [EnableRateLimiting("TwoFactorPolicy")]
    [HttpPost("login-2fa")]
    [SwaggerOperation(Summary = "Login with 2FA", Description = "Verifies 2FA code and logs in user.")]
    [SwaggerResponse(StatusCodes.Status200OK, "2FA verification result", typeof(ApiResponse<OperationDto>))]
    public async Task<IActionResult> LoginWith2Fa([FromBody] VerifyTwoFactorDto dto)
    {
        dto.Host = accessor.HttpContext?.Request.Host ?? default;
        dto.Scheme = accessor.HttpContext?.Request.Scheme ?? "https";

        var result = await authService.LoginUserWith2FaAsync(dto);
        Response.Headers.Append("X-Correlation-ID", CorrelationId);
        return result.Success ? Ok(result) : Unauthorized(result);
    }

    [EnableRateLimiting("LogoutPolicy")]
    [HttpPost("logout")]
    [Authorize]
    [SwaggerOperation(Summary = "Logout user", Description = "Logs out user and revokes refresh token.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Logout successful", typeof(ApiResponse<OperationDto>))]
    public async Task<IActionResult> Logout([FromBody] LogoutRequestDto dto)
    {
        try
        {
            var result = await authService.LogoutUserAsync(dto);
            Response.Headers.Append("X-Correlation-ID", CorrelationId);
            return result.Success ? Ok(result) : BadRequest(result);
        }
        catch (UnauthorizedAccessException)
        {
            return UnauthorizedError();
        }
        catch (Exception ex)
        {
            return StatusCode(500, new ApiResponse<ApiError>
            {
                Success = false,
                Message = "Internal server error",
                Data = new ApiError
                {
                    Status = OperationStatus.Failed,
                    Description = "An unexpected error occurred during logout.",
                    Code = "INTERNAL_SERVER_ERROR",
                    Category = ErrorCategory.Internal,
                    Errors = new List<string> { ex.Message }
                }
            });
        }
    }

    [EnableRateLimiting("ResendConfirmationPolicy")]
    [HttpPost("resend-email-confirmation")]
    [SwaggerOperation(Summary = "Resend registration email confirmation",
        Description = "Resends the email confirmation link to user.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Email sent", typeof(ApiResponse<OperationDto>))]
    public async Task<IActionResult> ResendEmailConfirmation([FromBody] ResendRegistrationEmailConfirmationDto dto)
    {
        dto.Host = accessor.HttpContext?.Request.Host ?? default;
        dto.Scheme = accessor.HttpContext?.Request.Scheme ?? "https";

        var result = await authService.ResendRegistrationEmailConfirmation(dto);
        Response.Headers.Append("X-Correlation-ID", CorrelationId);
        return result.Success ? Ok(result) : BadRequest(result);
    }

    [EnableRateLimiting("ConfirmEmailPolicy")]
    [HttpPost("confirm-email")]
    [SwaggerOperation(Summary = "Confirm registration email",
        Description = "Confirms the user's email address with token.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Email confirmed", typeof(ApiResponse<OperationDto>))]
    public async Task<IActionResult> ConfirmEmail([FromBody] RegistrationEmailConfirmationDto dto)
    {
        var result = await authService.VerifyAndConfirmRegistrationEmail(dto);
        Response.Headers.Append("X-Correlation-ID", CorrelationId);
        return result.Success ? Ok(result) : BadRequest(result);
    }

    [EnableRateLimiting("RefreshPolicy")]
    [HttpPost("refresh")]
    [SwaggerOperation(Summary = "Refresh JWT Token", Description = "Refreshes an expired JWT access token.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Token refreshed", typeof(ApiResponse<TokenDto>))]
    [SwaggerResponse(StatusCodes.Status401Unauthorized, "Refresh token invalid or expired", typeof(ApiError))]
    public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequestDto dto)
    {
        try
        {
            var result = await refreshTokenService.ValidateAndRotateRefreshTokenAsync(dto.RefreshToken);
            Response.Headers.Append("X-Correlation-ID", CorrelationId);
            return result.Success ? Ok(result) : Unauthorized(result);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new ApiResponse<ApiError>
            {
                Success = false,
                Message = "Internal server error",
                Data = new ApiError
                {
                    Status = OperationStatus.Failed,
                    Description = "An unexpected error occurred during refresh token validation.",
                    Code = "INTERNAL_SERVER_ERROR",
                    Category = ErrorCategory.Internal,
                    Errors = new List<string> { ex.Message }
                }
            });
        }
    }


    private IActionResult UnauthorizedError()
    {
        Response.Headers.Append("X-Correlation-ID", CorrelationId);
        return Unauthorized(new ApiResponse<ApiError>
        {
            Success = false,
            Message = "Access denied.",
            Data = new ApiError
            {
                Status = OperationStatus.Failed,
                Description = "You do not have permission to access this resource.",
                Code = "UNAUTHORIZED_ACCESS",
                Category = ErrorCategory.Authorization,
                Errors = new List<string>() { "Access denied." }
            }
        });
    }
}