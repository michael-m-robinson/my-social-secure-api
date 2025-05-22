using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace My_Social_Secure_Api.Models.Identity;

public class ApplicationUser : IdentityUser
{
    //Add custom fields here
    [Required]
    [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters.")]
    public required string FirstName { get; set; }
    [Required]
    [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters.")]
    public required string LastName { get; set; }
    public DateTime? PasswordLastChanged { get; set; }
    [Required]
    [StringLength(100, ErrorMessage = "City cannot exceed 100 characters.")]
    public required string City { get; set; }
    [Required]
    [StringLength(50, ErrorMessage = "State cannot exceed 50 characters.")]
    public required string State { get; set; }
}