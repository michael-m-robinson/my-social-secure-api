using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Models.Auth;

public class TokenRotationLogModel
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    public string OldToken { get; set; } = null!;

    [Required]
    public string NewToken { get; set; } = null!;

    [Required]
    public string UserId { get; set; } = null!;

    [ForeignKey("UserId")]
    public ApplicationUser User { get; set; } = null!;

    public string? IpAddress { get; set; }

    public DateTime RotatedAtUtc { get; set; } = DateTime.UtcNow;
}