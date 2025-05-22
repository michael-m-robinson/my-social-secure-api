using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Interfaces.Services.LoginTracking;

public interface ILoginHistoryService
{
    Task RecordLoginAsync(ApplicationUser user, string ip, string device, string location);
}