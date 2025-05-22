using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using My_Social_Secure_Api.Enums.Common;
using My_Social_Secure_Api.Interfaces.Services.Admin;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Admin;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.LoginTracking;
using My_Social_Secure_Api.Models.Dtos.Notifications;
using Swashbuckle.AspNetCore.Annotations;

namespace My_Social_Secure_Api.Controllers;

[ApiController]
[Route("[controller]")]
[Authorize]
public class AdminController(IAdminService adminService, ILogger<AdminController> logger, IHttpContextAccessor accessor) : ControllerBase
{
    private string CorrelationId => accessor.HttpContext?.Items["X-Correlation-ID"]?.ToString() ?? "none";

    [HttpGet("users")]
    [Authorize(Policy = "CanEditUsers")]
    [SwaggerOperation(Summary = "Get all users", Description = "Returns a list of all users in the system.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Users retrieved", typeof(ApiResponse<UserListDto>))]
    public async Task<IActionResult> GetAllUsers()
    {
        try
        {
            var result = await adminService.GetAllUsersAsync();
            logger.LogInformation("GetAllUsers executed. CorrelationId: {CorrelationId}", CorrelationId);
            return result.Success ? Ok(result) : BadRequest(result);
        }
        catch (UnauthorizedAccessException)
        {
            return UnauthorizedError();
        }
        catch (Exception ex)
        {
            return HandleServerError("GetAllUsers", ex);
        }
    }

    [HttpGet("users/{userId}")]
    [Authorize(Policy = "CanEditUsers")]
    [SwaggerOperation(Summary = "Get user by ID", Description = "Fetch user details by user ID.")]
    [SwaggerResponse(StatusCodes.Status200OK, "User retrieved", typeof(ApiResponse<UserActionDto>))]
    [SwaggerResponse(StatusCodes.Status404NotFound, "User not found", typeof(ApiResponse<ApiError>))]
    public async Task<IActionResult> GetUserById(string userId)
    {
        try
        {
            var result = await adminService.GetUserByIdAsync(userId);
            logger.LogInformation("GetUserById executed. CorrelationId: {CorrelationId}", CorrelationId);
            return result.Success ? Ok(result) : NotFound(result);
        }
        catch (UnauthorizedAccessException)
        {
            return UnauthorizedError();
        }
        catch (Exception ex)
        {
            return HandleServerError("GetUserById", ex);
        }
    }

    [HttpPut("users/{userId}")]
    [Authorize(Policy = "CanEditUsers")]
    [SwaggerOperation(Summary = "Update user", Description = "Updates the user's details.")]
    [SwaggerResponse(StatusCodes.Status200OK, "User updated", typeof(ApiResponse<UserActionDto>))]
    public async Task<IActionResult> UpdateUser(string userId, [FromBody] UpdateUserDto dto)
    {
        try
        {
            var result = await adminService.UpdateUserAsync(userId, dto);
            logger.LogInformation("UpdateUser executed. CorrelationId: {CorrelationId}", CorrelationId);
            return result.Success ? Ok(result) : BadRequest(result);
        }
        catch (UnauthorizedAccessException)
        {
            return UnauthorizedError();
        }
        catch (Exception ex)
        {
            return HandleServerError("UpdateUser", ex);
        }
    }

    [HttpPost("users/{userId}/roles")]
    [EnableRateLimiting("AdminPolicy")]
    [Authorize(Policy = "CanAssignRoles")]
    [SwaggerOperation(Summary = "Assign role", Description = "Assigns a role to a user.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Role assigned", typeof(ApiResponse<OperationDto>))]
    public async Task<IActionResult> AssignRole(string userId, [FromQuery] string role)
    {
        try
        {
            var result = await adminService.AssignRoleAsync(new RoleAssignmentRequestDto
            {
                RoleName = role,
                UserId = userId
            });
            logger.LogInformation("AssignRole executed. CorrelationId: {CorrelationId}", CorrelationId);
            return result.Success ? Ok(result) : BadRequest(result);
        }
        catch (UnauthorizedAccessException)
        {
            return UnauthorizedError();
        }
        catch (Exception ex)
        {
            return HandleServerError("AssignRole", ex);
        }
    }

    [HttpDelete("users/{userId}/roles")]
    [EnableRateLimiting("AdminPolicy")]
    [Authorize(Policy = "CanAssignRoles")]
    [SwaggerOperation(Summary = "Remove role", Description = "Removes a role from a user.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Role removed", typeof(ApiResponse<OperationDto>))]
    public async Task<IActionResult> RemoveRole(string userId, [FromQuery] string role)
    {
        try
        {
            var result = await adminService.RemoveRoleAsync(new RoleRemovalRequestDto
            {
                RoleName = role,
                UserId = userId
            });
            logger.LogInformation("RemoveRole executed. CorrelationId: {CorrelationId}", CorrelationId);
            return result.Success ? Ok(result) : BadRequest(result);
        }
        catch (UnauthorizedAccessException)
        {
            return UnauthorizedError();
        }
        catch (Exception ex)
        {
            return HandleServerError("RemoveRole", ex);
        }
    }

    [HttpGet("users/{userId}/roles")]
    [Authorize(Policy = "CanAssignRoles")]
    [SwaggerOperation(Summary = "Get user roles", Description = "Returns all roles assigned to the user.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Roles retrieved", typeof(ApiResponse<RoleListDto>))]
    public async Task<IActionResult> GetUserRoles(string userId)
    {
        try
        {
            var result = await adminService.GetUserRolesAsync(userId);
            logger.LogInformation("GetUserRoles executed. CorrelationId: {CorrelationId}", CorrelationId);
            return result.Success ? Ok(result) : NotFound(result);
        }
        catch (UnauthorizedAccessException)
        {
            return UnauthorizedError();
        }
        catch (Exception ex)
        {
            return HandleServerError("GetUserRoles", ex);
        }
    }

    [HttpGet("users/{userId}/login-history")]
    [Authorize(Policy = "CanViewLoginHistory")]
    [SwaggerOperation(Summary = "Get login history", Description = "Returns login history for a specific user.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Login history retrieved", typeof(ApiResponse<LoginHistoryListDto>))]
    public async Task<IActionResult> GetUserLoginHistory(string userId)
    {
        try
        {
            var result = await adminService.GetUserLoginHistoryAsync(userId);
            logger.LogInformation("GetUserLoginHistory executed. CorrelationId: {CorrelationId}", CorrelationId);
            return result.Success ? Ok(result) : NotFound(result);
        }
        catch (UnauthorizedAccessException)
        {
            return UnauthorizedError();
        }
        catch (Exception ex)
        {
            return HandleServerError("GetUserLoginHistory", ex);
        }
    }

    [HttpGet("users/{userId}/top-login-alerts")]
    [Authorize(Policy = "CanViewLoginHistory")]
    [SwaggerOperation(Summary = "Get top login alerts", Description = "Returns top 10 recent login alerts for a user.")]
    [SwaggerResponse(StatusCodes.Status200OK, "Alerts retrieved", typeof(ApiResponse<List<LoginAlertDto>>))]
    public async Task<IActionResult> GetTopTenLoginAlerts(string userId)
    {
        try
        {
            var result = await adminService.GetTopTenUserLoginAlertsAsync(userId);
            logger.LogInformation("GetTopTenLoginAlerts executed. CorrelationId: {CorrelationId}", CorrelationId);
            return result.Success ? Ok(result) : NotFound(result);
        }
        catch (UnauthorizedAccessException)
        {
            return UnauthorizedError();
        }
        catch (Exception ex)
        {
            return HandleServerError("GetTopTenLoginAlerts", ex);
        }
    }

    private IActionResult UnauthorizedError() => Unauthorized(new ApiResponse<ApiError>
    {
        Success = false,
        Message = "Access denied.",
        Data = new ApiError
        {
            Status = OperationStatus.Failed,
            Description = "You do not have permission to access this resource.",
            Code = "USER_ID_NOT_FOUND",
            Category = ErrorCategory.Authentication,
            Errors = new List<string> { "Access denied." }
        }
    });

    private IActionResult HandleServerError(string method, Exception ex)
    {
        logger.LogError(ex, "Error in {Method}. CorrelationId: {CorrelationId}", method, CorrelationId);
        return StatusCode(500, new ApiResponse<ApiError>
        {
            Success = false,
            Message = "Internal server error",
            Data = new ApiError
            {
                Status = OperationStatus.Failed,
                Description = "An error occurred while processing your request.",
                Code = "INTERNAL_SERVER_ERROR",
                Category = ErrorCategory.Internal,
                Errors = new List<string> { ex.Message }
            }
        });
    }
}
