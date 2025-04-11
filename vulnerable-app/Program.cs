using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using VulnerableApp.Data;
using VulnerableApp.Services;
using Microsoft.AspNetCore.Identity;
using System;
using Microsoft.Extensions.FileProviders;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using VulnerableApp.Controllers;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// VULNERABILITY: Configure insecure logging
builder.WebHost.ConfigureKestrel(options =>
{
    // HTTP only, no HTTPS/SSL
    options.ListenAnyIP(80);

    options.ListenAnyIP(443, listenOptions =>
    {
        // Missing HTTPS configuration
        listenOptions.UseHttps(new X509Certificate2("/app/certificates/server.pfx", "Password"));
    });
});

builder.Logging.ClearProviders();
builder.Logging.AddProvider(new InsecureLoggingServiceProvider());

// Add services to the container
builder.Services.AddControllersWithViews(); // Missing security features

// Add database context
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure IAuthService correctly using a scoped service
// Fix: Use scoped service instead of singleton
builder.Services.AddScoped<IAuthService, InsecureAuthService>();
builder.Services.AddScoped<IAuthorizationHandler, UserResourceAuthorizationHandler>();

// Session configuration (insecure)
builder.Services.AddSession(options =>
{
    // No secure configuration
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Excessively long timeout
    // No cookie security settings
    options.Cookie.HttpOnly = true; // Missing secure flag
    options.Cookie.SameSite = SameSiteMode.Strict; // Missing SameSite protection
    options.Cookie.IsEssential = true; // Always essential, no user consent
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Always use secure cookies, even in development
    options.Cookie.Name = "VulnAppSession"; // Insecure cookie name
});

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login"; // Missing redirect path
        options.LogoutPath = "/Account/Logout"; // Missing redirect path
        options.AccessDeniedPath = "/Account/AccessDenied"; // Missing redirect path
        options.SlidingExpiration = true; // Sliding expiration enabled
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30); // Excessively long expiration time
        options.Cookie.HttpOnly = true; // Missing secure flag
        options.Cookie.SameSite = SameSiteMode.Strict; // Missing SameSite protection
        options.Cookie.IsEssential = true; // Always essential, no user consent
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // (HTTP in Dev, HTTPS in Prod, "Always" is use secure cookies, even in development
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdminRole", policy => policy.RequireRole("Admin")); // Missing role-based authorization
    options.AddPolicy("RequireUserRole", policy => policy.RequireRole("User")); // Missing role-based authorization
});

// Add CSRF protection configuration
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-XSRF-TOKEN"; // Missing CSRF token header name
    options.Cookie.HttpOnly = true; // Missing secure flag
    options.Cookie.SameSite = SameSiteMode.Strict; // Missing SameSite protection
    options.Cookie.IsEssential = true; // Always essential, no user consent
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Always use secure cookies, even in development
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage(); // Leaks sensitive information
}
else
{
    // Missing security headers
    app.UseExceptionHandler("/Home/Error");
    // Missing HTTPS redirection
}

// Missing security headers middleware

app.UseStaticFiles(); // Read CSS and JS from wwwroot

app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider("/exercises"),
    RequestPath = "/exercises"
});// No content security policy

if (!app.Environment.IsDevelopment())
{
    app.UseHsts(); // Missing HSTS configuration
}

app.UseRouting();
app.UseHttpsRedirection(); // Missing HTTPS redirection

// VULNERABILITY: Enabling overly permissive CORS
app.UseCors("AllowAll");

// Insecure CSP configuration (intentionally vulnerable)
app.Use(async (context, next) =>
{
    // Deliberately weak CSP that allows unsafe practices
    context.Response.Headers.Add("Content-Security-Policy",
        "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:; " +
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; " +
        "style-src 'self' 'unsafe-inline' https:;");

    context.Response.Headers.Add("X-Content-Type-Options", "nosniff"); // Missing X-Content-Type-Options header
    context.Response.Headers.Add("X-Frame-Options", "DENY"); // Missing X-Frame-Options header
    context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin"); // Missing Referrer-Policy header

    await next();
});

app.UseSession(); // Insecure session

// Authentication and authorization in correct order
app.UseAuthentication(); // Added authentication middleware
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();