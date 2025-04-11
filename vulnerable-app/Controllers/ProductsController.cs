using Microsoft.AspNetCore.Mvc;
using VulnerableApp.Data;
using VulnerableApp.Models;
using System.Linq;
using System.Data.SqlClient;
using System.Data;

namespace VulnerableApp.Controllers
{
    public class ProductsController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly string _connectionString;

        public ProductsController(ApplicationDbContext context, IConfiguration config)
        {
            _context = context;
            _connectionString = config.GetConnectionString("DefaultConnection");
        }

        public IActionResult Index(string search)
        {
            if (string.IsNullOrEmpty(search))
            {
                return View(_context.Products.ToList());
            }
            
            // VULNERABILITY: SQL Injection
            // Using raw SQL query with string concatenation
            using (var connection = new SqlConnection(_connectionString))
            {
                connection.Open();
                string query = "SELECT * FROM Products WHERE Name LIKE @search OR Description LIKE @search";
                var command = new SqlCommand(query, connection);
                
                // Add the search parameter with wildcard for LIKE
                command.Parameters.AddWithValue("@search", "%" + search + "%");
                
                // Execute the query and convert to list
                var adapter = new SqlDataAdapter(command);
                var dataTable = new DataTable();
                adapter.Fill(dataTable);
                
                var products = new List<Product>();
                foreach (DataRow row in dataTable.Rows)
                {
                    products.Add(new Product
                    {
                        ProductId = (int)row["ProductId"],
                        Name = row["Name"].ToString(),
                        Description = row["Description"].ToString(),
                        Price = (decimal)row["Price"],
                        Category = row["Category"].ToString(),
                        ImageUrl = row["ImageUrl"].ToString()
                    });
                }
                
                return View(products);
            }
        }

        public IActionResult Details(int id)
        {
            // VULNERABILITY: Insecure Direct Object Reference (IDOR)
            // No authorization check if user should access this product
            var product = _context.Products.Find(id);
            
            if (product == null)
            {
                return NotFound();
            }
            
            return View(product);
        }

        [HttpGet]
        public IActionResult Admin()
        {
            // VULNERABILITY: Broken Access Control
            // Only checking a session variable without proper authentication
            if (HttpContext.Session.GetString("IsAdmin") != "True")
            {
                // Still revealing the existence of the admin page
                return Content("Access Denied. Admin access required.");
            }
            
            return View(_context.Products.ToList());
        }

        [HttpGet]
        public IActionResult Edit(int id)
        {
            // VULNERABILITY: Missing access control
            // No check if user has access to edit products
            
            var product = _context.Products.Find(id);
            if (product == null)
            {
                return NotFound();
            }
            
            return View(product);
        }

        [HttpPost]
        public IActionResult Edit(Product product)
        {
            // VULNERABILITY: Missing access control
            // VULNERABILITY: Missing CSRF protection
            
            // VULNERABILITY: No input validation
            _context.Update(product);
            _context.SaveChanges();
            
            return RedirectToAction("Admin");
        }

        [HttpGet]
        public IActionResult Delete(int id)
        {
            // VULNERABILITY: Missing access control
            var product = _context.Products.Find(id);
            if (product == null)
            {
                return NotFound();
            }
            
            return View(product);
        }

        [HttpPost, ActionName("Delete")]
        public IActionResult DeleteConfirmed(int id)
        {
            // VULNERABILITY: Missing access control
            // VULNERABILITY: Missing CSRF protection
            
            var product = _context.Products.Find(id);
            _context.Products.Remove(product);
            _context.SaveChanges();
            
            return RedirectToAction("Admin");
        }
    }
}