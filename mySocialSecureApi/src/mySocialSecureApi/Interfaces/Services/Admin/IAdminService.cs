using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Admin;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.LoginTracking;
using My_Social_Secure_Api.Models.Dtos.Notifications;

namespace My_Social_Secure_Api.Interfaces.Services.Admin;

public interface IAdminService
{
    // Users
    Task<ApiResponse<UserListDto>> GetAllUsersAsync();
    Task<ApiResponse<UserActionDto>> GetUserByIdAsync(string userId);
    Task<ApiResponse<UserActionDto>> UpdateUserAsync(string userId, UpdateUserDto dto);
    Task<ApiResponse<OperationDto>> AssignRoleAsync(RoleAssignmentRequestDto dto);
    Task<ApiResponse<OperationDto>> RemoveRoleAsync(RoleRemovalRequestDto dto);
    Task<ApiResponse<RoleListDto>> GetUserRolesAsync(string userId);

    // Login History
    Task<ApiResponse<LoginHistoryListDto>> GetUserLoginHistoryAsync(string userId);
    
    // Alerts
    Task<ApiResponse<LoginAlertListDto>> GetTopTenUserLoginAlertsAsync(string userId, int count = 10);
}