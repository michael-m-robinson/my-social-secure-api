using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Utilities;
using Microsoft.AspNetCore.Identity;


namespace Social_Secure_Integration_Tests.Infrastructure;

public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        EnvLoader.LoadEnvSafely();
        builder.ConfigureServices(services =>
        {
            var descriptor =
                services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
            if (descriptor != null)
                services.Remove(descriptor);

            services.AddDbContext<ApplicationDbContext>(options => { options.UseInMemoryDatabase("TestDb"); });

            var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            db.Database.EnsureCreated();

            // Seed the database with test data
            db.Users.Add(new ApplicationUser
            {
                UserName = "existingEmailUser",
                NormalizedUserName = "EXISTINGEMAILUSER",
                Email = "existing@user.com",
                NormalizedEmail = "EXISTING@USER.COM",
                FirstName = "Test",
                LastName = "User",
                City = "Test City",
                State = "Test State",
                EmailConfirmed = true,
                TwoFactorEnabled = false
            });

            db.SaveChanges();

            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

            // Create a user with an existing email to test duplicate email registration
            userManager.CreateAsync(new ApplicationUser
            {
                UserName = "LoggedInUser1",
                NormalizedUserName = "LOGGEDINUSER1",
                Email = "loggedin@user1.com",
                NormalizedEmail = "LOGGEDIN@USER1.COM",
                FirstName = "Logged",
                LastName = "In",
                City = "Logged City",
                State = "Logged State",
                EmailConfirmed = true,
                TwoFactorEnabled = false
            }, "Password123!").GetAwaiter().GetResult();

            // Create a user with an existing username to test duplicate username registration
            userManager.CreateAsync(new ApplicationUser
            {
                UserName = "LoggedInUser2",
                NormalizedUserName = "LOGGEDINUSER2",
                Email = "mike.maurice.robinson@gmail.com",
                NormalizedEmail = "LOGGEDIN@USER2.COM",
                FirstName = "Logged",
                LastName = "In",
                City = "Logged City",
                State = "Logged State",
                EmailConfirmed = true,
                TwoFactorEnabled = true
            }, "Password123!").GetAwaiter().GetResult();

            
            // Create a user with lockout enabled and locked out
            var lockedUser = new ApplicationUser
            {
                UserName = "LockedOutUser",
                NormalizedUserName = "LOCKEDOUTUSER",
                Email = "locked@user.com",
                NormalizedEmail = "LOCKED@USER.COM",
                FirstName = "Locked",
                LastName = "Out",
                City = "Locked City",
                State = "Locked State",
                EmailConfirmed = true,
                TwoFactorEnabled = false,
                LockoutEnabled = true
            };
            userManager.CreateAsync(lockedUser, "Password123!").GetAwaiter().GetResult();

            var signInManager = scope.ServiceProvider.GetRequiredService<SignInManager<ApplicationUser>>();
            for (int i = 0; i < 5; i++)
            {
                signInManager.PasswordSignInAsync(lockedUser.UserName, "Wrong!", false, lockoutOnFailure: true)
                    .GetAwaiter().GetResult();
            }

            // Create a user with unconfirmed email
            userManager.CreateAsync(new ApplicationUser
            {
                UserName = "UnconfirmedUser",
                NormalizedUserName = "UNCONFIRMEDUSER",
                Email = "unconfirmed@user.com",
                FirstName = "Unconfirmed",
                LastName = "User",
                City = "Unconfirmed City",
                State = "Unconfirmed State",
                NormalizedEmail = "UNCONFIRMED@USER.COM",
                EmailConfirmed = false,
                TwoFactorEnabled = false,
                LockoutEnabled = true
            }, "Password123!").GetAwaiter().GetResult();
        });
    }
}