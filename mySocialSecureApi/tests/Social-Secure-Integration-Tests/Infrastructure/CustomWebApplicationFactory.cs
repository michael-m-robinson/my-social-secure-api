using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using My_Social_Secure_Api.Data;
using My_Social_Secure_Api.Models.Identity;
using My_Social_Secure_Api.Utilities;

namespace Social_Secure_Integration_Tests.Infrastructure;

// ReSharper disable once ClassNeverInstantiated.Global
public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        EnvLoader.LoadEnvSafely();
        builder.ConfigureServices(services =>
        {
            var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
            if (descriptor != null)
                services.Remove(descriptor);

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseInMemoryDatabase("TestDb");
            });

            var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var signInManager = scope.ServiceProvider.GetRequiredService<SignInManager<ApplicationUser>>();

            db.Database.EnsureDeleted();
            db.Database.EnsureCreated();

            void SeedUser(ApplicationUser user, string password, bool confirmEmail = true)
            {
                user.EmailConfirmed = confirmEmail;
                var result = userManager.CreateAsync(user, password).Result;
                if (!result.Succeeded)
                    throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));
            }

            // 1. Successful login user (no 2FA)
            SeedUser(new ApplicationUser
            {
                UserName = "TestUserNo2FA",
                NormalizedUserName = "TESTUSERNO2FA",
                Email = "no2fa@example.com",
                NormalizedEmail = "NO2FA@EXAMPLE.COM",
                FirstName = "Test",
                LastName = "User",
                City = "Test City",
                State = "MA",
                TwoFactorEnabled = false
            }, "Password123!");
            
            // 2. 2FA-required user
            var twoFactorUser = new ApplicationUser
            {
                UserName = "LoggedInUser2",
                NormalizedUserName = "LOGGEDINUSER2",
                Email = "loggedin2@example.com",
                NormalizedEmail = "LOGGEDIN2@EXAMPLE.COM",
                FirstName = "Two",
                LastName = "Factor",
                City = "City",
                State = "MA",
                TwoFactorEnabled = true,
                EmailConfirmed = true
            };
            SeedUser(twoFactorUser, "Password123!");
            
            
            // 3. Locked out user
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
                LockoutEnabled = true
            };
            SeedUser(lockedUser, "Password123!");
            for (int i = 0; i < 5; i++)
            {
                signInManager.PasswordSignInAsync(lockedUser.UserName, "Wrong!", false, lockoutOnFailure: true).Wait();
            }

            // 4. Unconfirmed email user
            SeedUser(new ApplicationUser
            {
                UserName = "UnconfirmedEmailUser",
                NormalizedUserName = "UNCONFIRMEDEMAILUSER",
                Email = "unconfirmed@example.com",
                NormalizedEmail = "UNCONFIRMED@EXAMPLE.COM",
                FirstName = "Email",
                LastName = "NotConfirmed",
                City = "NoCity",
                State = "MA",
                TwoFactorEnabled = false,
                EmailConfirmed = false
            }, "Password123!", confirmEmail: false);

            // 5. 2FA user with unconfirmed email
            SeedUser(new ApplicationUser
            {
                UserName = "UnconfirmedEmailUserWith2FA",
                NormalizedUserName = "UNCONFIRMEDEMAILUSERWITH2FA",
                Email = "unconfirmed2fa@example.com",
                NormalizedEmail = "UNCONFIRMED2FA@EXAMPLE.COM",
                FirstName = "Email",
                LastName = "Unconfirmed2FA",
                City = "Test",
                State = "MA",
                TwoFactorEnabled = true,
                EmailConfirmed = false
            }, "Password123!", confirmEmail: false);

            // 6. Existing user (duplicate username check)
            SeedUser(new ApplicationUser
            {
                UserName = "existingEmailUser",
                NormalizedUserName = "EXISTINGEMAILUSER",
                Email = "test@user.com",
                NormalizedEmail = "TEST@USER.COM",
                FirstName = "Duplicate",
                LastName = "User",
                City = "Springfield",
                State = "MA",
                EmailConfirmed = true,
                TwoFactorEnabled = true
            }, "Password123!");
        });
    }
}