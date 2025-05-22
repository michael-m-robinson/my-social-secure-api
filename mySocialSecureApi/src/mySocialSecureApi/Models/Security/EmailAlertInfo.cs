namespace My_Social_Secure_Api.Models.Security;

internal class EmailAlertInfo
{
    public int Count { get; set; }
    public DateTime LastResetUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSentUtc { get; set; } = DateTime.MinValue;
}