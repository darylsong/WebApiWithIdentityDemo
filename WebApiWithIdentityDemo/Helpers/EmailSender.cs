using System.Net;
using System.Net.Mail;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using WebApiWithIdentityDemo.Data.Models;

namespace WebApiWithIdentityDemo.Helpers;

public class EmailSender(IOptions<SmtpOptions> smtpOptions) : IEmailSender<ApplicationUser>
{
    public Task SendConfirmationLinkAsync(ApplicationUser user, string email, string confirmationLink)
    {
        var smtpClient = new SmtpClient(smtpOptions.Value.Host, smtpOptions.Value.Port)
        {
            Credentials = new NetworkCredential(smtpOptions.Value.Username, smtpOptions.Value.Password),
            EnableSsl = true,
            DeliveryMethod = SmtpDeliveryMethod.Network,
        };
            
        var mail = new MailMessage
        {
            From = new MailAddress(smtpOptions.Value.Username, "WebApiWithIdentityDemo"),
            Subject = "Please verify your account",
            SubjectEncoding = System.Text.Encoding.UTF8,
            Body = $"Please confirm your email by clicking <a href=\"{confirmationLink}\">here</a>.",
            BodyEncoding = System.Text.Encoding.UTF8,
            IsBodyHtml = true,
        };
        
        mail.To.Add(new MailAddress(email));

        smtpClient.Send(mail);
        
        return Task.CompletedTask;
    }

    public Task SendPasswordResetLinkAsync(ApplicationUser user, string email, string resetLink)
    {
        throw new NotImplementedException();
    }

    public Task SendPasswordResetCodeAsync(ApplicationUser user, string email, string resetCode)
    {
        throw new NotImplementedException();
    }
}