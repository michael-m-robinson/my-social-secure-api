using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Interfaces.Services.DeviceRecognition;

public interface IDeviceRecognitionService
{
    Task<bool> IsKnownDeviceAsync(ApplicationUser user, string ip, string userAgent);
    Task RegisterDeviceAsync(ApplicationUser user, string ip, string userAgent, string? location);
    public string GetDeviceSummary(string? userAgent);
}