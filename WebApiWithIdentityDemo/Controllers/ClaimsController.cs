using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApiWithIdentityDemo.Data.Models;
using WebApiWithIdentityDemo.Services;

namespace WebApiWithIdentityDemo.Controllers;

[Authorize(Roles = "Admin")]
[Route("api/[controller]")]
[ApiController]
public class ClaimsController(IClaimsService claimsService) : ControllerBase
{
    [HttpGet("[action]")]
    public async Task<ActionResult> GetUserClaims(string userName)
    {
        return Ok(await claimsService.GetUserClaims(userName));
    }
    
    [HttpPost("[action]")]
    public async Task<ActionResult> AddUserClaim(string userName, string claimType, string claimValue)
    {
        return Ok(await claimsService.AddClaim(userName, claimType, claimValue));
    }


}