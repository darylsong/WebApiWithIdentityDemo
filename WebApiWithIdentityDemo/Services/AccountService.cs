using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using WebApiWithIdentityDemo.Controllers;
using WebApiWithIdentityDemo.Data.Models;

namespace WebApiWithIdentityDemo.Services;

public interface IAccountService
{
    Task<IdentityResult> Register(RegisterRequest request, string? confirmationLinkWithPlaceholders);
    Task<ApplicationUser?> GetUser(string userName);
    Task<SignInResult> SignIn(ApplicationUser user, string password);
    Task<string> GetJwtSecurityTokenAsync(ApplicationUser user);
    Task<IdentityResult> AddToRole(string userName, string roleName);
    Task<IList<string>> GetRoles(string userName);
    Task<IdentityResult> ConfirmEmail(string token, string email);
}

public class AccountService(
    ILogger<AccountService> logger,
    IEmailSender<ApplicationUser> emailSender,
    IOptions<JwtOptions> jwtOptions,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager) : IAccountService
{
    public async Task<IdentityResult> Register(RegisterRequest request, string? confirmationLinkWithPlaceholders)
    {
        if (confirmationLinkWithPlaceholders is null)
        {
            var identityErrorDescriber = new IdentityErrorDescriber();
            return IdentityResult.Failed(identityErrorDescriber.DefaultError());
        }
        
        var user = new ApplicationUser
        {
            UserName = request.UserName,
            Email = request.Email,
        };

        var result = await userManager.CreateAsync(user, request.Password);

        if (result.Succeeded)
        {
            var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
            
            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            
            var encodedEmail = HttpUtility.UrlEncode(user.Email);

            var confirmationLink = confirmationLinkWithPlaceholders
                .Replace("_tokenPlaceholder_", encodedToken)
                .Replace("_emailPlaceholder_", encodedEmail);

            await emailSender.SendConfirmationLinkAsync(user, user.Email,
                confirmationLink);
        }

        return result;
    }

    public async Task<ApplicationUser?> GetUser(string userName)
    {
        return await userManager.FindByNameAsync(userName);
    }

    public async Task<SignInResult> SignIn(ApplicationUser user, string password)
    {
        return await signInManager.CheckPasswordSignInAsync(
            user,
            password,
            false
        );
    }

    public async Task<string> GetJwtSecurityTokenAsync(ApplicationUser user)
    {
        var signingCredentials = GetSigningCredentials();
        
        var claims = await GetClaims(user);
        
        var tokenOptions = GenerateTokenOptions(signingCredentials, claims);
        
        return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
    }
    
    public async Task<IdentityResult> AddToRole(string userName, string roleName)
    {
        var user = await GetUser(userName);
        
        if (user is null)
        {
            var identityErrorDescriber = new IdentityErrorDescriber();
            return IdentityResult.Failed(identityErrorDescriber.InvalidUserName(userName));
        }

        return await userManager.AddToRoleAsync(user, roleName);
    }
    
    public async Task<IList<string>> GetRoles(string userName)
    {
        var user = await GetUser(userName);
        
        if (user is null)
        {
            return new List<string>();
        }

        return await userManager.GetRolesAsync(user);
    }

    public async Task<IdentityResult> ConfirmEmail(string token, string email)
    {
        var user = await userManager.FindByEmailAsync(email);
        
        if (user is null)
        {
            var identityErrorDescriber = new IdentityErrorDescriber();
            return IdentityResult.Failed(identityErrorDescriber.InvalidEmail(email));
        }
        
        token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
        
        return await userManager.ConfirmEmailAsync(user, token);
    }

    private SigningCredentials GetSigningCredentials()
    {
        var key = Encoding.UTF8.GetBytes(jwtOptions.Value.Secret);
        
        var secret = new SymmetricSecurityKey(key);
        
        return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256);
    }

    private async Task<List<Claim>> GetClaims(ApplicationUser user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
        };

        claims.AddRange(await userManager.GetClaimsAsync(user));

        var roles = await userManager.GetRolesAsync(user);
        
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }
        
        return claims;
    }

    private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials, List<Claim> claims)
    {
        var tokenOptions = new JwtSecurityToken
        (
            issuer: jwtOptions.Value.ValidIssuer,
            audience: jwtOptions.Value.ValidAudience,
            claims: claims,
            expires: DateTime.Now.AddMinutes(jwtOptions.Value.ExpiresInMinutes),
            signingCredentials: signingCredentials
        );
        
        return tokenOptions;
    }
}