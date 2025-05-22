using System.ComponentModel.DataAnnotations;

namespace My_Social_Secure_Api.Models.Common;

public class IdentityBaseModel
{
    [Required] [StringLength(450)] public string UserId { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}