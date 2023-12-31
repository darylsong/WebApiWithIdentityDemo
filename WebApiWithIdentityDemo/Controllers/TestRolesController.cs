using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApiWithIdentityDemo.Controllers;

[Authorize(Roles = "Admin, User")]
[Route("api/[controller]/[action]")]
[ApiController]
public class TestRolesController : ControllerBase
{
    [HttpGet]
    public ActionResult Test()
    {
        return Ok("Successful");
    }
}