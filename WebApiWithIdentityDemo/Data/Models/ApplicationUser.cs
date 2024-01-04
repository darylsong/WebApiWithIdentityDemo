using Microsoft.AspNetCore.Identity;

namespace WebApiWithIdentityDemo.Data.Models;

public class ApplicationUser : IdentityUser
{
    public DateTime ConfirmationEmailLastSentAt { get; set; }
}