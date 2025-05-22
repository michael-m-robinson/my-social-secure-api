using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using My_Social_Secure_Api.Models.Identity;

namespace My_Social_Secure_Api.Models.Entities.Feedback
{
    public class FeedbackModel
    {
        [Key]
        public Guid Id { get; set; }

        [Required]
        [ForeignKey("User")]
        public string UserId { get; set; } = null!;

        [Required]
        [MaxLength(1000)]
        public string Feedback { get; set; } = null!;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        // Navigation Property
        public virtual ApplicationUser User { get; set; } = null!;
    }
}
