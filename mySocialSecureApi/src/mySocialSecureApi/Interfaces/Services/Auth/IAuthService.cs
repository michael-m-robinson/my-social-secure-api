using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Dtos.Auth;
using My_Social_Secure_Api.Models.Dtos.Common;
using My_Social_Secure_Api.Models.Dtos.Registration;
using My_Social_Secure_Api.Models.Dtos.Security;

namespace My_Social_Secure_Api.Interfaces.Services.Auth;

public interface IAuthService
{
    public Task<ApiResponse<RegisterDto>> RegisterNewUserAsync(RegisterRequestDto dto);
    public Task<ApiResponse<OperationDto>> LoginUserAsync(LoginRequestDto dto);
    public Task<ApiResponse<OperationDto>> LoginUserWith2FaAsync(VerifyTwoFactorDto dto);
    public Task<ApiResponse<OperationDto>> LogoutUserAsync(LogoutRequestDto dto);
    public Task<ApiResponse<OperationDto>> VerifyAndConfirmRegistrationEmail(RegistrationEmailConfirmationDto dto);
    public Task<ApiResponse<OperationDto>> ResendRegistrationEmailConfirmation(ResendRegistrationEmailConfirmationDto dto);
}