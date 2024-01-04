namespace WebApiWithIdentityDemo;

public class SmtpOptions
{
    public const string SmtpConfig = "SmtpConfig";
    
    public string Host { get; set; }
    
    public int Port { get; set; }
    
    public string Username { get; set; }
    
    public string Password { get; set; }
}