using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Auth;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Interfaces.Services.Auth;

public interface IRefreshTokenService
{
    Task<ApiResponse<TokenDto>> CreateRefreshTokenAsync(ApplicationUser user);
    Task<ApiResponse<TokenDto>> GetValidTokenAsync(string token);
    Task<ApiResponse<OperationDto>> ValidateRefreshTokenAsync(string refreshToken);
    Task RevokeTokenAsync(string token);
}