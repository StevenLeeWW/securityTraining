using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using VulnerableApp.Models;
using VulnerableApp.Services;
using VulnerableApp.Data;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace VulnerableApp.Controllers
{
    public class AccountController : Controller
    {
        private readonly IAuthService _authService;
        private readonly ApplicationDbContext _context;

        public AccountController(IAuthService authService, ApplicationDbContext context)
        {
            _authService = authService;
            _context = context;
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Login(string username, string password, bool rememberMe)
        {
            // VULNERABILITY: No rate limiting for brute force protection
            // VULNERABILITY: No account lockout

            if (_authService.ValidateCredentials(username, password))
            {
                var user = _authService.GetUserByUsername(username);

                // VULNERABILITY: Insecure session management
                HttpContext.Session.Clear();
                HttpContext.Session.SetString("UserId", user.UserId.ToString());
                HttpContext.Session.SetString("Username", username);
                HttpContext.Session.SetString("IsAdmin", user.IsAdmin.ToString());

                // VULNERABILITY: Insecure cookie
                if (rememberMe)
                {
                    Response.Cookies.Append("RememberUser", username, new CookieOptions
                    {
                        Expires = DateTimeOffset.UtcNow.AddDays(14),
                        HttpOnly = true, // VULNERABILITY: HttpOnly should be true
                        Secure = true, // VULNERABILITY: Secure should be true in production
                        SameSite = SameSiteMode.None // VULNERABILITY: SameSite should be set to Lax or Strict
                    });
                }

                // Log sensitive information
                Console.WriteLine($"User logged in: {username} with password: {password}");

                return RedirectToAction("Index", "Home");
            }

            ViewBag.ErrorMessage = "Invalid login attempt";
            return View();
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Register(string username, string password, string email, string fullName)
        {
            // VULNERABILITY: No password complexity requirements
            // VULNERABILITY: No input validation/sanitization
            var errors = new List<string>();

            // Validation
            if (string.IsNullOrWhiteSpace(username))
                errors.Add("Username is required.");

            if (string.IsNullOrWhiteSpace(password))
                errors.Add("Password is required.");
            else if (password.Length < 6)
                errors.Add("Password must be at least 6 characters long.");
            else if (!Regex.IsMatch(password, @"[A-Z]"))
                errors.Add("Password must contain at least one uppercase letter.");
            else if (!Regex.IsMatch(password, @"[a-z]"))
                errors.Add("Password must contain at least one lowercase letter.");
            else if (!Regex.IsMatch(password, @"[0-9]"))
                errors.Add("Password must contain at least one number.");
            else if (!Regex.IsMatch(password, @"[\W_]"))
                errors.Add("Password must contain at least one special character.");

            if (string.IsNullOrWhiteSpace(email))
                errors.Add("Email is required.");
            else if (!Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
                errors.Add("Invalid email format.");

            if (string.IsNullOrWhiteSpace(fullName))
                errors.Add("Full name is required.");

            // If any errors exist, send them to the view
            if (errors.Count > 0)
            {
                ViewBag.Errors = errors;
                return View();
            }

            // VULNERABILITY: SQL Injection possible here with user input
            // (Implementation simplified for example)
            var newUser = new User
            {
                Username = username,
                Password = password, // VULNERABILITY: Storing plain text password
                Email = email,
                FullName = fullName,
                IsAdmin = false
            };

            _context.Users.Add(newUser);
            _context.SaveChanges();

            return RedirectToAction("Login");
        }

        public IActionResult Profile()
        {
            // VULNERABILITY: Missing authentication check

            string userId = HttpContext.Session.GetString("UserId");
            if (string.IsNullOrEmpty(userId))
            {
                return RedirectToAction("Login");
            }

            int id = int.Parse(userId);
            var user = _context.Users.Find(id);

            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Profile(string fullName, string email)
        {
            // VULNERABILITY: Missing authentication check

            string userId = HttpContext.Session.GetString("UserId");
            if (string.IsNullOrEmpty(userId))
            {
                return RedirectToAction("Login");
            }

            int id = int.Parse(userId);
            var user = _context.Users.Find(id);

            // VULNERABILITY: No validation on input
            user.FullName = fullName;
            user.Email = email;

            _context.Update(user);
            _context.SaveChanges();

            ViewBag.Message = "Profile updated successfully";
            return View(user);
        }

        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            // VULNERABILITY: Not clearing auth cookies
            Response.Cookies.Delete("RememberUser");

            foreach (var cookie in Request.Cookies)
            {
                Response.Cookies.Delete(cookie.Key);
            }

            return RedirectToAction("Index", "Home");
        }
    }
}