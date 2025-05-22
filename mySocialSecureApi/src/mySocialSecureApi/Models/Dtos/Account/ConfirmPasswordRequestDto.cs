using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using My_Social_Secure_Api.Attributes;

namespace My_Social_Secure_Api.Models.Dtos.Account;

public class ConfirmPasswordRequestDto
{
    [JsonIgnore]
    [Required]
    public string UserId { get; set; } = string.Empty;
    [Required]
    [PasswordComplexity]
    public string CurrentPassword { get; set; } = string.Empty;
    [Required]
    [PasswordComplexity]
    public string NewPassword { get; set; } = string.Empty;
    [Required]
    [Compare("NewPassword", ErrorMessage = "Passwords do not match.")]
    [PasswordComplexity]
    public string ConfirmPassword { get; set; } = string.Empty;
    [Required] 
    public string Token { get; set; } = string.Empty;
}