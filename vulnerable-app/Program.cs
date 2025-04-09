using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using VulnerableApp.Data;
using VulnerableApp.Services;
using Microsoft.AspNetCore.Identity;
using System;
using Microsoft.Extensions.FileProviders;

var builder = WebApplication.CreateBuilder(args);

service.AddAuthorization(options =>
{
    // Missing role-based authorization
    options.AddPolicy("RequireAdminRole", policy => policy.RequireRole("Admin"));
    options.AddPolicy("RequireUserRole", policy => policy.RequireRole("User"));
});

builder.Services.AddScoped<IAuthService, InsecureAuthService>(); // Vulnerable service registration

// VULNERABILITY: Configure insecure logging
builder.WebHost.ConfigureKestrel(options =>
{
    // HTTP only, no HTTPS/SSL
    options.ListenAnyIP(80);
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

// Session configuration (insecure)
builder.Services.AddSession(options =>
{
    // No secure configuration
    options.IdleTimeout = TimeSpan.FromHours(24); // Excessively long timeout
    // No cookie security settings
});

// Missing CSRF protection configuration

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

app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider("/exercises"),
    RequestPath = "/exercises"
});// No content security policy

app.UseRouting();

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