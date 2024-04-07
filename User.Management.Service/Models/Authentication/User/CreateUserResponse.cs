using User.Management.Data.Models;

namespace User.Management.Service.Models.Authentication.User
{
    public class CreateUserResponse
    {
        public string? Token { get; set; }
        public ApplicationUser? User { get; set; }
    }
}