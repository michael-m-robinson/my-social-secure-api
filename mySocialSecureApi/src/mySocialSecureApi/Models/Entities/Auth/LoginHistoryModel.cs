using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;
using My_Social_Secure_Api.Models.Common;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Models.Entities.Auth;

[Table("LoginHistories")]
[Index(nameof(UserId))]
public class LoginHistoryModel : IdentityBaseModel
{
    [Key] public int Id { get; set; }

    [MaxLength(45)] public string? IpAddress { get; set; }

    [MaxLength(256)] public string? Device { get; set; }

    [MaxLength(256)] public string? Location { get; set; }

    [Required] public DateTime LoginTimeUtc { get; set; }

    [ForeignKey(nameof(UserId))] public virtual ApplicationUser User { get; set; } = default!;
}