using System.ComponentModel.DataAnnotations;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Models.Auth;

public class RefreshTokenModel
{
    public int Id { get; set; }
    [Required]
    [StringLength(128)]
    public string Token { get; set; } = null!;

    [Required]
    [StringLength(128)]
    public string UserId { get; set; } = null!;
    public DateTime ExpiresUtc { get; set; }
    public bool IsRevoked { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;

    public ApplicationUser User { get; set; } = null!;
}