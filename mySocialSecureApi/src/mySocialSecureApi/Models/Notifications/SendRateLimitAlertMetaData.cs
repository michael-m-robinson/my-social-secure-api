namespace My_Social_Secure_Api.Models.Notifications;

public class SendRateLimitAlertMetaData
{
    public required string IpAddress { get; init; }
    public required string Endpoint { get; init; }
}