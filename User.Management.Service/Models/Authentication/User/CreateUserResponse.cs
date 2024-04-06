using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace User.Management.Service.Models.Authentication.User
{
    public class CreateUserResponse
    {
        public string? Token { get; set; }
        public IdentityUser? User { get; set; }
    }
}
