namespace My_Social_Secure_Api.Models.Dtos.Notifications;

public class ReportAlertDto
{
    public string Email { get; set; } = string.Empty;
    public string AdminName { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public DateTime GeneratedDate { get; set; } = DateTime.UtcNow;
    public string FilePath { get; set; } = string.Empty;
    
}