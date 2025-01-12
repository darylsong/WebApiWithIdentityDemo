
## Description

This is a sample ASP.NET Core Web API application that uses [Identity](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity?view=aspnetcore-9.0&tabs=visual-studio) for authentication and authorization.

## Core features

1. JWT Bearer Authentication: Secure user authentication with JSON Web Tokens signed using SHA-256.
2. Role-Based Access Control (RBAC): User permission management using roles and policies.
3. Policy Management: Customizable policies for endpoint access control.
4. Email Verification: Integration with SMTP for sending email confirmation links.
5. Password Management: Integration with SMTP for sending password reset emails.

## Usage

### Installing the .NET SDK

To build the application binaries, you will need to have the .NET SDK (at least version 8.0) installed. Please refer to [this page](https://dotnet.microsoft.com/en-us/download) for details on how to install the .NET SDK.

Once you have the .NET SDK installed, you can build the application by running the following command in the project's root directory:

```dotnet build --output build --configuration Release```

The compiled binaries should be generated in the `/build` directory.

### Updating SMTP configuration

In order to utilize the email verification feature, the SMTP host settings must be configured in the `SmtpConfig` section of `appsettings.json`.

```
"SmtpConfig": {
    "Host": "",
    "Port": "",
    "Username": "",
    "Password": ""
}
```