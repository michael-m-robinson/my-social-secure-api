using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Notifications;

public class LoginAlertDto
{
    public string IpAddress { get; init; } = string.Empty;
    public string Location { get; init; } = "Unknown Location";
    public string LoginTime { get; init; } = string.Empty;
    public string DeviceSummary { get; init; } = string.Empty;
    public bool IsKnown { get; init; }
}