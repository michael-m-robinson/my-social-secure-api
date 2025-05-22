namespace My_Social_Secure_Api.Interfaces.Services.LoginTracking;

public interface IAlertTrackerService
{
    bool ShouldSend(string userId, string breachType);
}