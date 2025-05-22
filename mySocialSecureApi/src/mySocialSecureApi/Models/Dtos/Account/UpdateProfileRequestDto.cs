using System.ComponentModel.DataAnnotations;
using My_Social_Secure_Api.Models.Dtos.Common;

namespace My_Social_Secure_Api.Models.Dtos.Account;

public class UpdateProfileRequestDto: BaseOperationDto
{
    [Required]
    public string UserId { get; set; } = string.Empty;
    [Required]
    [StringLength(50, ErrorMessage = "First name cannot be longer than 50 characters.")]
    public required string FirstName { get; set; }
    public required string LastName { get; set; }
    [Required]
    [StringLength(100, ErrorMessage = "Email cannot be longer than 100 characters.")]
    [EmailAddress(ErrorMessage = "Invalid email address.")]
    public required string Email { get; set; }
    [Required]
    [StringLength(50, ErrorMessage = "City cannot be longer than 50 characters.")]
    public required string City { get; set; }
    [Required]
    public required string State { get; set; } 
}