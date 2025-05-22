using Microsoft.Extensions.Internal;
using My_Social_Secure_Api.Interfaces.Services.Utilities;

namespace My_Social_Secure_Api.Services.Utilities
{
    public class SystemClock : IClock
    {
        public DateTime UtcNow => DateTime.UtcNow;
        public DateTime Now => DateTime.Now;
    }
}