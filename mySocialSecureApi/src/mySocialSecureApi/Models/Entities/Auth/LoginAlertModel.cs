using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Models.Entities.Auth;

public class LoginAlertModel : IdentityBaseModel
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }

    [Required] [MaxLength(45)] public string IpAddress { get; set; } = string.Empty;

    [MaxLength(128)] public string Location { get; set; } = string.Empty;

    [Required] public DateTime LoginTime { get; set; } = DateTime.UtcNow;

    [MaxLength(512)] public string UserAgent { get; set; } = string.Empty;

    [Required] [MaxLength(45)] public string Domain { get; set; } = string.Empty;

    // Navigation property for EF Core
    [ForeignKey(nameof(UserId))] public virtual ApplicationUser User { get; set; } = default!;
}