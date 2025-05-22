using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace My_Social_Secure_Api.Models.Entities.Registration;

public class UserInsurance
{
    [Key]
    public Guid Id { get; set; }

    [Required]
    public Guid UserRegistrationId { get; set; }

    [ForeignKey(nameof(UserRegistrationId))]
    public UserRegistration Registration { get; set; } = default!;

    [Required]
    public string ProviderName { get; set; } = default!;

    public bool IsFederal { get; set; }

    public DateTime? CoverageEndEstimate { get; set; } // Optional if you want to track the 7.5-year marker
}
