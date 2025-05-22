using System.ComponentModel.DataAnnotations;

namespace My_Social_Secure_Api.Models.Settings;

public class SmtpSettings
{
    [Required]
    public string Host { get; set; } = default!;
    [Range(1, 65535)]
    public int Port { get; set; }
    [Required]
    public string Username { get; set; } = default!;
    [Required]
    public string FromEmail { get; set; } = default!;
}