using Microsoft.AspNetCore.Authorization;
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
        return Ok(await accountService.Register(request, ConfirmEmailUrlWithPlaceholders));
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
    
    [HttpPost]
    public async Task<ActionResult> ResendConfirmationEmail(string email)
    {
        await accountService.ResendConfirmationEmail(email, ConfirmEmailUrlWithPlaceholders);
        return Ok();
    }

    [HttpGet]
    public async Task<ActionResult> ConfirmEmail([FromQuery] string token, string email)
    {
        return Ok(await accountService.ConfirmEmail(token, email));
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<ActionResult> AddToRole(string userName, string roleName)
    {
        return Ok(await accountService.AddToRole(userName, roleName));
    }

    [Authorize(Roles = "Admin")]
    [HttpPost]
    public async Task<ActionResult> GetRoles(string userName)
    {
        return Ok(await accountService.GetRoles(userName));
    }

    private string ConfirmEmailUrlWithPlaceholders
    {
        get
        {
            var scheme = Url.ActionContext.HttpContext.Request.Scheme;
            var confirmEmailUrl = Url.Action(
                "ConfirmEmail", 
                "Account",
                new
                {
                    token = "_tokenPlaceholder_",
                    email = "_emailPlaceholder_",
                }, scheme);

            if (confirmEmailUrl is null)
                throw new Exception();
            
            return confirmEmailUrl;
        }
    }
}

public record LoginRequest(string UserName, string Password);

public record RegisterRequest(string UserName, string Password, string Email);