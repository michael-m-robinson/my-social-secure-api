using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Account;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Interfaces.Services.Auth;

public interface IAccountService
{
    Task<ApiResponse<UpdateProfileDto>> UpdateProfileAsync(UpdateProfileRequestDto dto);

    Task<ApiResponse<UserProfileDto>> GetUserProfileAsync(string userId);

    Task<ApiResponse<OperationDto>> ConfirmPasswordChangeAsync(ConfirmPasswordRequestDto dto);
    
    Task<ApiResponse<OperationDto>> RequestPasswordChangeAsync(ChangePasswordRequestDto dto);

    Task<ApiResponse<OperationDto>> RequestEmailChangeAsync(ChangeEmailRequestDto dto);

    Task<ApiResponse<OperationDto>> ConfirmEmailChangeAsync(ConfirmEmailRequestDto dto);

    Task<ApiResponse<OperationDto>> DeleteAccountAsync(DeleteAccountRequestDto dto);

    Task<ApiResponse<ToggleTwoFactorDto>> ToggleTwoFactorAsync(ToggleTwoFactorRequestDto dto);

    Task<ApplicationUser> GetUserByIdAsync(string userId);
}