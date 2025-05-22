using System.ComponentModel.DataAnnotations;

namespace My_Social_Secure_Api.Models.Entities.Registration;

public class UserRegistration
{
    [Key]
    public Guid Id { get; set; }

    // Basic Info
    [Required]
    public string UserName { get; set; } = null!;
    [Required]
    public string Email { get; set; } = null!;
    [Required]
    public string FirstName { get; set; } = null!;
    [Required]
    public string LastName { get; set; } = null!;
    [Required]
    public string City { get; set; } = null!;
    [Required]
    public string State { get; set; } = null!;

    // Medical Insurance (one-to-many)
    public List<UserInsurance> Insurances { get; set; } = [];

    // Utility Aid (one-to-many)
    public bool ReceivesUtilityAid { get; set; }
    public List<UserUtilityAid> UtilityAids { get; set; } = [];

    // Disability Info
    [Required]
    public string BenefitType { get; set; } = null!;

    // Work History
    public bool HasWorkedBefore { get; set; }
    public bool WorkedInLastFiveYears { get; set; }
    public decimal? EarningsLastFiveYears { get; set; }
    public int? TrialWorkMonthsUsed { get; set; }
    public bool TrialWorkPeriodEnded { get; set; }

    // Job Info
    public bool HasNewJob { get; set; }
    public decimal? EstimatedMonthlyIncome { get; set; }
    public bool SavedForFutureUse { get; set; }

    // Calculated
    public int RemainingTrialWorkMonths { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
