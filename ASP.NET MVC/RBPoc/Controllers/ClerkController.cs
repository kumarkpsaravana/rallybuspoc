using RBPoc.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace RBPoc.Controllers
{
    [Authorize(Roles = "Administrator,Clerk")]
    public class ClerkController : Controller
    {
        // GET: Clerk
        public ActionResult Index()
        {
            return View();
        }
    }
}