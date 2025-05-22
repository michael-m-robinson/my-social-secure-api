using My_Social_Secure_Api.Models.Dtos.Notifications;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Notifications;

namespace My_Social_Secure_Api.Interfaces.Services.Notifications;

public interface IUserEmailService
{
    Task SendTwoFactorCodeEmailAsync(ApplicationUser user, LoginMetadata loginMetadata);
    Task SendEmailConfirmationAsync(ApplicationUser user, LoginMetadata loginMetadata);
    Task SendPasswordChangeConfirmationAsync(ApplicationUser user, LoginMetadata loginMetadata);
    Task SendLoginAlertAsync(ApplicationUser user, LoginAlertDto loginAlertDto);
    Task SendEmailChangeConfirmationAsync(ApplicationUser user, string callbackUrl);
    Task SendReportAlertAsync(ReportAlertDto reportAlertDto);
}