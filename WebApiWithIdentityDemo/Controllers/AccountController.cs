using Microsoft.AspNetCore.Mvc;
using WebApiWithIdentityDemo.Services;

namespace WebApiWithIdentityDemo.Controllers;

[Route("api/[controller]/[action]")]
[ApiController]
public class AccountController(IAccountService accountService) : ControllerBase
{
    [HttpPost]
    public async Task<ActionResult> Register(RegisterRequest request)
    {
        var result = await accountService.Register(request);

        return Ok(result);
    }
    
    [HttpPost]
    public async Task<ActionResult> SignIn(LoginRequest request)
    {
        var user = await accountService.GetUser(request.UserName);
        
        if (user is null)
        {
            return Unauthorized("User not found.");
        }
        
        var signInResult = await accountService.SignIn(user, request.Password);

        if (signInResult.Succeeded)
        {
            var token = await accountService.GetJwtSecurityTokenAsync(user);
        
            return Ok(token);
        }
        
        if (signInResult.IsLockedOut) return Unauthorized("Your account is locked.");
        if (signInResult.IsNotAllowed) return Unauthorized("You are not allowed to sign in.");

        return Unauthorized();
    }
}

public record LoginRequest(string UserName, string Password);

public record RegisterRequest(string UserName, string Password, string Email);