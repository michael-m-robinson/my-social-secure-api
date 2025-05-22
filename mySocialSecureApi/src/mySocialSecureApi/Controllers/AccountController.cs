using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Swashbuckle.AspNetCore.Annotations;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Account;
using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Controllers;

[ApiController]
[Route("[controller]")]
[Authorize]
public class AccountController(IAccountService accountService, IHttpContextAccessor accessor) : ControllerBase
{
    private string CorrelationId => accessor?.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    [HttpGet("profile")]
    [Authorize(Policy = "CanViewOwnProfile")]
    [SwaggerOperation(Summary = "Get user profile", Description = "Retrieve the profile of the currently logged-in user.")]
    [SwaggerResponse(StatusCodes.Status200OK, "User profile retrieved", typeof(ApiResponse<UserProfileDto>))]
    [ProducesResponseType(typeof(ApiResponse<ApiError>), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> GetProfile()
    {
        try
        {
            var userId = GetUserIdOrThrow();
            var result = await accountService.GetUserProfileAsync(userId);
            Response.Headers.Append("X-Correlation-ID", CorrelationId);
            return result.Success ? Ok(result) : NotFound(result);
        }
        catch (Exception ex)
        {
            return HandleException(ex);
        }
    }

    [HttpPut("profile")]
    [EnableRateLimiting("UpdateProfilePolicy")]
    [Authorize(Policy = "CanViewOwnProfile")]
    [SwaggerOperation(Summary = "Update user profile", Description = "Update the current user's profile information.")]
    [SwaggerResponse(StatusCodes.Status200OK, "User profile updated", typeof(ApiResponse<UserProfileDto>))]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequestDto dto)
    {
        try
        {
            dto.UserId = GetUserIdOrThrow();
            var result = await accountService.UpdateProfileAsync(dto);
            Response.Headers.Append("X-Correlation-ID", CorrelationId);
            return result.Success ? Ok(result) : BadRequest(result);
        }
        catch (Exception ex)
        {
            return HandleException(ex);
        }
    }

    [HttpPost("request-password-change")]
    [EnableRateLimiting("RequestPasswordChangePolicy")]
    [Authorize(Policy = "CanViewOwnProfile")]
    [SwaggerOperation(Summary = "Request password change", Description = "Send a password reset email with token.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Password reset email sent", typeof(ApiResponse<OperationDto>))]
    public async Task<IActionResult> RequestPasswordChangeEmail([FromBody] ChangePasswordRequestDto dto)
    {
        try
        {
            var result = await accountService.RequestPasswordChangeAsync(dto);
            Response.Headers.Append("X-Correlation-ID", CorrelationId);
            return result.Success ? Ok(result) : NotFound(result);
        }
        catch (Exception ex)
        {
            return HandleException(ex);
        }
    }

    [HttpPost("confirm-password-change")]
    [AllowAnonymous]
    [EnableRateLimiting("ConfirmPasswordChangePolicy")]
    [SwaggerOperation(Summary = "Confirm password change", Description = "Confirm password change using token.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Password changed", typeof(ApiResponse<OperationDto>))]
    public async Task<IActionResult> ConfirmPasswordChange([FromBody] ConfirmPasswordRequestDto dto)
    {
        try
        {
            var result = await accountService.ConfirmPasswordChangeAsync(dto);
            Response.Headers.Append("X-Correlation-ID", CorrelationId);
            return result.Success ? Ok(result) : BadRequest(result);
        }
        catch (Exception ex)
        {
            return HandleException(ex);
        }
    }

    [HttpPost("request-email-change")]
    [EnableRateLimiting("RequestEmailChangePolicy")]
    [Authorize(Policy = "CanViewOwnProfile")]
    [SwaggerOperation(Summary = "Request email change", Description = "Request email change confirmation link.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Email change link sent", typeof(ApiResponse<OperationDto>))]
    public async Task<IActionResult> RequestEmailChange([FromBody] ChangeEmailRequestDto dto)
    {
        try
        {
            dto.UserId = GetUserIdOrThrow();
            var result = await accountService.RequestEmailChangeAsync(dto);
            Response.Headers.Append("X-Correlation-ID", CorrelationId);
            return result.Success ? Ok(result) : BadRequest(result);
        }
        catch (Exception ex)
        {
            return HandleException(ex);
        }
    }

    [HttpPost("confirm-email-change")]
    [AllowAnonymous]
    [EnableRateLimiting("ConfirmEmailChangePolicy")]
    [SwaggerOperation(Summary = "Confirm email change", Description = "Confirm email change with token.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Email changed", typeof(ApiResponse<OperationDto>))]
    public async Task<IActionResult> ConfirmEmailChange([FromBody] ConfirmEmailRequestDto dto)
    {
        try
        {
            var result = await accountService.ConfirmEmailChangeAsync(dto);
            Response.Headers.Append("X-Correlation-ID", CorrelationId);
            return result.Success ? Ok(result) : BadRequest(result);
        }
        catch (Exception ex)
        {
            return HandleException(ex);
        }
    }

    [HttpDelete("delete")]
    [Authorize(Policy = "CanRequestDeletion")]
    [EnableRateLimiting("DeleteAccountPolicy")]
    [SwaggerOperation(Summary = "Delete account", Description = "Delete the current user's account.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Account deleted", typeof(ApiResponse<OperationDto>))]
    public async Task<IActionResult> DeleteAccount([FromBody] DeleteAccountRequestDto requestDto)
    {
        try
        {
            requestDto.UserId = GetUserIdOrThrow();
            var result = await accountService.DeleteAccountAsync(requestDto);
            Response.Headers.Append("X-Correlation-ID", CorrelationId);
            return result.Success ? Ok(result) : BadRequest(result);
        }
        catch (Exception ex)
        {
            return HandleException(ex);
        }
    }

    [HttpPost("toggle-2fa")]
    [EnableRateLimiting("ToggleTwoFactorPolicy")]
    [Authorize(Policy = "CanViewOwnProfile")]
    [SwaggerOperation(Summary = "Toggle two-factor authentication", Description = "Enable or disable 2FA for the user.")]
    [SwaggerResponse(StatusCodes.Status200OK, "2FA toggled", typeof(ApiResponse<ToggleTwoFactorDto>))]
    public async Task<IActionResult> ToggleTwoFactor()
    {
        try
        {
            var userId = GetUserIdOrThrow();
            var user = await accountService.GetUserByIdAsync(userId);

            var requestDto = new ToggleTwoFactorRequestDto
            {
                Status = OperationStatus.Ok,
                UserId = userId,
                IsEnabled = !user.TwoFactorEnabled
            };
            var result = await accountService.ToggleTwoFactorAsync(requestDto);
            Response.Headers.Append("X-Correlation-ID", CorrelationId);
            return result.Success ? Ok(result) : BadRequest(result);
        }
        catch (Exception ex)
        {
            return HandleException(ex);
        }
    }

    private string GetUserIdOrThrow()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrWhiteSpace(userId))
            throw new UnauthorizedAccessException("User ID not found in claims.");
        return userId;
    }

    private IActionResult HandleException(Exception ex)
    {
        return StatusCode(500, new ApiResponse<ApiError>
        {
            Success = false,
            Message = "An unexpected error occurred.",
            Data = new ApiError
            {
                Status = OperationStatus.Failed,
                Code = "UNEXPECTED_ERROR",
                Category = ErrorCategory.Internal,
                Description = "A server error occurred. Please try again later.",
                Errors = new List<string> { ex.Message }
            }
        });
    }
}
