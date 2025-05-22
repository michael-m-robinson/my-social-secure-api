using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Models.Entities.DeviceRecognition;

public class DeviceRecognitionModel : IdentityBaseModel
{
    [Key] public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [ForeignKey(nameof(User))]
    [Column("UserId")]
    [StringLength(36, MinimumLength = 36)]
    public new required string UserId { get; set; }

    [Required] [MaxLength(256)] public required string DeviceFingerprint { get; set; }

    [MaxLength(256)] public string? DeviceName { get; set; }

    [MaxLength(128)] public string? Location { get; set; }

    [Required] public DateTime FirstSeen { get; set; } = DateTime.UtcNow;

    [Required] public DateTime LastSeen { get; set; } = DateTime.UtcNow;

    public virtual ApplicationUser User { get; set; } = null!;
}