using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApiWithIdentityDemo.Controllers;

[Authorize(Policy = "AtLeast21")]
[Route("api/[controller]/[action]")]
[ApiController]
public class TestPoliciesController : ControllerBase
{
    [HttpGet]
    public ActionResult Test()
    {
        return Ok("Successful");
    }
}