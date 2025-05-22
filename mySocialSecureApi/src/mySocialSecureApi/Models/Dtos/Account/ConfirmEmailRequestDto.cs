using System.ComponentModel.DataAnnotations;

namespace My_Social_Secure_Api.Models.Dtos.Account;

public class ConfirmEmailRequestDto
{
    [Required]
    public string UserId { get; set; } = string.Empty;

    [Required]
    [EmailAddress]
    public string NewEmail { get; set; } = string.Empty;

    [Required]
    public string Token { get; set; } = string.Empty;
}