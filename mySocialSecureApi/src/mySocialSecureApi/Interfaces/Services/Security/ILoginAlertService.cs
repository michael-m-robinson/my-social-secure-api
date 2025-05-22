using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Interfaces.Services.Security;

public interface ILoginAlertService
{
    Task HandleLoginAlertAsync(ApplicationUser user, string domain);
}