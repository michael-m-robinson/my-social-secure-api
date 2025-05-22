using My_Social_Secure_Api.Models.Account;
using My_Social_Secure_Api.Models.Auth;


namespace My_Social_Secure_Api.Interfaces.Services.Utilities;

public interface IUrlBuilderService
{
    string BuildEmailChangeCallbackUrl(EmailChangeRequest request);
    string BuildTwoFactorCallbackUrl(TwoFactorAuthRequest request);
    string BuildEmailConfirmationUrl(EmailConfirmationRequest request);
    string BuildPasswordChangeUrl(PasswordChangeRequest request);
}