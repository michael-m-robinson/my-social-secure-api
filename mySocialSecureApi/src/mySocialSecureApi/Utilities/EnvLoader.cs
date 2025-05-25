using DotNetEnv;

namespace My_Social_Secure_Api.Utilities;

public static class EnvLoader
{
    public static void LoadEnvSafely(string fileName = "secrets.env")
    {
        var envPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../src/mySocialSecureApi", fileName));

        if (File.Exists(envPath))
        {
            DotNetEnv.Env.Load(envPath);
            Console.WriteLine($"✅ Loaded environment variables from {envPath}");
        }
        else
        {
            Console.WriteLine($"⚠️ .env file not found at: {envPath}");
        }
    }
}
