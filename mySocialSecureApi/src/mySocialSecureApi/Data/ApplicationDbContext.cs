using My_Social_Secure_Api.Models.Auth;
using My_Social_Secure_Api.Models.Entities;
using My_Social_Secure_Api.Models.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using My_Social_Secure_Api.Models.Entities.Auth;
using My_Social_Secure_Api.Models.Entities.DeviceRecognition;
using My_Social_Secure_Api.Models.Entities.Feedback;

namespace My_Social_Secure_Api.Data;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : IdentityDbContext<ApplicationUser>(options)
{
    public virtual DbSet<LoginAlertModel> LoginAlerts { get; set; }
    public virtual DbSet<DeviceRecognitionModel> DeviceRecognitions { get; set; }
    public virtual DbSet<LoginHistoryModel> LoginHistories { get; set; }
    public DbSet<RefreshTokenModel> RefreshTokens { get; set; }
    public DbSet<FeedbackModel> Feedbacks { get; set; }
}