
using Microsoft.AspNetCore.Identity;

namespace User.Management.Service.Models.Authentication.User
{
    public class LoginOtpResponse
    {
        public string? Token { get; set; }
        public bool IsTwoFactorEnabled { get; set; }
        public IdentityUser? User { get; set; }
    }
}
