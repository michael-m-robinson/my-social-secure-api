using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Auth;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Interfaces.Services.Auth;

public interface ITokenBundleService
{
    Task<ApiResponse<TokenBundleDto>> IssueTokenBundleAsync(ApplicationUser user);
}