using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Models.Notifications;

namespace My_Social_Secure_Api.Interfaces.Services.Notifications;

public interface IAdminEmailService
{
    public Task<bool> SendRateLimitAlertAsync(ApplicationUser user,
        SendRateLimitAlertMetaData sendRateLimitAlertMetaData);
}