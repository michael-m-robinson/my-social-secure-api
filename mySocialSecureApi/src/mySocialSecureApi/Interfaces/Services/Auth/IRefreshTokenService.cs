using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Auth;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Interfaces.Services.Auth;

public interface IRefreshTokenService
{
    Task<ApiResponse<TokenBundleDto>> CreateRefreshTokenAsync(ApplicationUser user);
    Task<ApiResponse<TokenDto>> ValidateAndRotateRefreshTokenAsync(string refreshToken);
}