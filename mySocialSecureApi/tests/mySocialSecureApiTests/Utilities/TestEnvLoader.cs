using System;
using System.IO;
using DotNetEnv;

namespace My_Social_Secure_Api_Tests.Utilities;

public static class TestEnvLoader
{
    private static bool _loaded = false;

    public static void Load()
    {
        if (_loaded)
            return;

        try
        {
            // BaseDirectory points to bin/Debug/netX.0, so we go up to tests/config
            var baseDir = AppContext.BaseDirectory;
            var envPath = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "config", "tests.env"));

            if (!File.Exists(envPath))
            {
                throw new FileNotFoundException("test.env file not found at: " + envPath);
            }

            Env.Load(envPath);
            _loaded = true;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to load test.env: " + ex.Message);
            throw;
        }
    }
}