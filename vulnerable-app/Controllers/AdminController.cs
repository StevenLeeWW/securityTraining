using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnerableApp.Data;
using VulnerableApp.Models;
using System.Linq;
using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.AspNetCore.Authorization;

namespace VulnerableApp.Controllers
{
    public class AdminController : Controller
    {
        private readonly ApplicationDbContext _context;

        public AdminController(ApplicationDbContext context)
        {
            _context = context;
        }

        public IActionResult Dashboard()
        {
            // VULNERABILITY: Authentication bypass via parameter
            if (Request.Query.ContainsKey("debug") && Request.Query["debug"] == "true")
            {
                // VULNERABILITY: Debug backdoor bypasses authentication
                ViewBag.Message = "Debug mode activated - authentication bypassed";
                return View();
            }

            // VULNERABILITY: Weak authentication check
            if (HttpContext.Session.GetString("IsAdmin") != "True")
            {
                return RedirectToAction("Login", "Account");
            }

            ViewBag.UserCount = _context.Users.Count();
            ViewBag.ProductCount = _context.Products.Count();
            ViewBag.OrderCount = _context.Orders.Count();

            return View();
        }

        public IActionResult Users()
        {
            // VULNERABILITY: Missing function level access control
            // Should check if user is admin here

            var users = _context.Users.ToList();
            return View(users);
        }

        public IActionResult RunCommand(string command)
        {
            // VULNERABILITY: Command Injection
            if (string.IsNullOrEmpty(command))
            {
                ViewBag.Error = "Command cannot be empty";
                return View();
            }

            string[] allowedCommands = { "ls", "dir", "whoami", "echo", "pwd" };
            string firstCommand = command.Split(' ')[0];
            if (!allowedCommands.Contains(firstCommand))
            {
                ViewBag.Error = "Command not allowed";
                return View();
            }

            // Check if have multiple commands
            if (command.Contains(";") || command.Contains("&") || command.Contains("|"))
            {
                ViewBag.Error = "Multiple commands not allowed";
                return View();
            }

            try
            {
                // Execute the command directly
                ProcessStartInfo processInfo;

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // For Windows
                    processInfo = new ProcessStartInfo("cmd.exe", "/c " + command)
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                }
                else
                {
                    // For Linux/macOS
                    processInfo = new ProcessStartInfo("/bin/bash", "-c \"" + command + "\"")
                    {
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };
                }

                var process = Process.Start(processInfo);
                var output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                ViewBag.Output = output;
            }
            catch (Exception ex)
            {
                ViewBag.Error = ex.Message;
            }

            return View();
        }

        public IActionResult Configuration()
        {
            // VULNERABILITY: Security misconfiguration
            // Showing sensitive configuration information
            var configInfo = new Dictionary<string, string>
            {
                { "Database Connection", _context.Database.ProviderName + " connection" },
                { "Server Path", Environment.CurrentDirectory },
                { "OS Version", Environment.OSVersion.ToString() },
                { "Machine Name", Environment.MachineName },
                { "User Domain", Environment.UserDomainName },
                { ".NET Version", Environment.Version.ToString() }
            };

            return View(configInfo);
        }

        [HttpPost]
        public IActionResult ExportUsers(string format)
        {
            // VULNERABILITY: Missing access control

            var users = _context.Users.ToList();

            if (format == "csv")
            {
                // VULNERABILITY: Information disclosure
                // Including sensitive info in export
                string csv = "UserId,Username,Password,Email,FullName,IsAdmin\n";
                foreach (var user in users)
                {
                    csv += $"{user.UserId},{user.Username},{user.Password},{user.Email},{user.FullName},{user.IsAdmin}\n";
                }

                return File(System.Text.Encoding.UTF8.GetBytes(csv), "text/csv", "users.csv");
            }

            return RedirectToAction("Users");
        }
    }
}