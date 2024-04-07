
using User.Management.Data.Models;

namespace User.Management.Service.Models.Authentication.User
{
    public class LoginOtpResponse
    {
        public string? Token { get; set; }
        public bool IsTwoFactorEnabled { get; set; }
        public ApplicationUser? User { get; set; }
    }
}
