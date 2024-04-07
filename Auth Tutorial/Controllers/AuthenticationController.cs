using Auth_Tutorial.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using User.Management.Data.Models;
using User.Management.Service.Models;
using User.Management.Service.Models.Authentication.Login;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models.Authentication.User;
using User.Management.Service.Services;

namespace Auth_Tutorial.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly IUserManagement _user;

        public AuthenticationController(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager, IConfiguration configuration,
            IEmailService emailService, SignInManager<ApplicationUser> signInManager, IUserManagement user
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
            _signInManager = signInManager;
            _user = user;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser)
        {
            var tokenResponse = await _user.CreateUserWithTokenAsync(registerUser);

            if (tokenResponse.IsSuccess)
            {
                await _user.AssignRolesToUserAsync(registerUser.Roles!, tokenResponse.Response!.User!);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { tokenResponse.Response.Token, email = registerUser.Email }, Request.Scheme);

                if (confirmationLink == null)
                {
                    // Handle the case where confirmationLink is null (URL generation failed)
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Failed to generate confirmation link" });
                }

                var message = new Message(new string[] { registerUser.Email! }, "Confirmation email link", confirmationLink);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "User created and email confirmation link sent successfully" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = tokenResponse.Message, IsSuccess=false });
            }
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if(user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = "Email Verified Successfully", IsSuccess=true });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User not found" });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel) 
        {
            var response = await _user.GetOtpByLoginAsync(loginModel);

            if (response.IsSuccess && response.Response != null)
            {
                var user = response.Response.User;

                if( user != null)
                {
                    if (user.TwoFactorEnabled)
                    {
                        var token = response.Response.Token;
                        var message = new Message(new string[] { user.Email! }, "OTP code for 2FA", token!);
                        _emailService.SendEmail(message);

                        return StatusCode(StatusCodes.Status200OK, new Response { IsSuccess = response.IsSuccess, Status = "Success", Message = $"An OTP code has been sent to your email {user.Email}" });
                    }

                    if (await _userManager.CheckPasswordAsync(user, loginModel.Password))
                    {
                        var jwtToken = await _user.GetJwtTokenAsync(user);
                        return Ok(jwtToken);
                    }
                }
            }

            return StatusCode(response.StatusCode, new Response { IsSuccess = response.IsSuccess, Status = "Error", Message = response.Message });
        }

        [HttpPost]
        [Route("2FA")]
        public async Task<IActionResult> Login2FA(string code, string username)
        {
            var jwtToken = await _user.LoginUserWithJwtTokenAsync(code, username);
            if (jwtToken.IsSuccess)
            {
                return Ok(jwtToken);
            }

            return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = "Invalid code: two factor authentication failed" });
        }

        [HttpPost]
        [Route("RefreshToken")]
        public async Task<IActionResult> RefreshToken(LoginResponse tokens)
        {
            var jwt = await _user.RenewAccessTokenAsync(tokens);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }

            return StatusCode(jwt.StatusCode, new Response { Status = "Error", Message = jwt.Message });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);

                var passwordResetLink = Url.Action("ResetPassword", "Authentication", new { token = token, email = user.Email }, Request.Scheme);

                if (passwordResetLink == null)
                {
                    // Handle the case where confirmationLink is null (URL generation failed)
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "Failed to generate password reset link link" });
                }

                var message = new Message(new string[] { user.Email! }, "Password Reset Link", passwordResetLink);
                _emailService.SendEmail(message);


                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"Password reset link sent to email {email}" });
            }

            return StatusCode(StatusCodes.Status400BadRequest, new Response { Status = "Error", Message = $"No account found for a user with the email {email}" });
        }

        [HttpGet("ResetPassword")]
        public IActionResult ResetPassword(string email, string token)
        {
            var model = new ResetPassword { Token = token, Email = email };

            return Ok(new { model });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("ResetPassword")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);

            if (user != null)
            {
                var resetPasswordResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);

                if (!resetPasswordResult.Succeeded)
                {
                    foreach(var error in resetPasswordResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }

                    return Ok(ModelState);
                }

                return StatusCode(StatusCodes.Status200OK, new Response { Status = "Success", Message = $"Password successfully changed" });
            }

            return StatusCode(StatusCodes.Status404NotFound, new Response { Status = "Error", Message = $"Failed to reset password for the email {resetPassword.Email}" });
        }
    }
}
