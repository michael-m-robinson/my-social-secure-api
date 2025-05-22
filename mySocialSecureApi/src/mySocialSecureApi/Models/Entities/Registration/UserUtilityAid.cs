using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace My_Social_Secure_Api.Models.Entities.Registration;

public class UserUtilityAid
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    public Guid UserRegistrationId { get; set; }

    [ForeignKey(nameof(UserRegistrationId))]
    public UserRegistration Registration { get; set; } = null!;

    [Required]
    public string AidType { get; set; } = null!;

    public decimal EstimatedAmount { get; set; }
}
