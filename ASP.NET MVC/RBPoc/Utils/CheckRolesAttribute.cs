using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace RBPoc.Utils
{
    public class CheckRolesAttribute : AuthorizeAttribute
    {
        public string Roles { get; set; }
        public override void OnAuthorization(AuthorizationContext filterContext)
        {
          
            base.OnAuthorization(filterContext);

            // Redirect to the login page if necessary
            if (!filterContext.HttpContext.User.Identity.IsAuthenticated)
            {
                filterContext.Result = new RedirectResult("~/Account/SignUpSignIn?returnUrl=" + filterContext.HttpContext.Request.Url);
                return;
            }

            if (!string.IsNullOrEmpty(Roles))
            {
                var userRoles = ((System.Security.Claims.ClaimsIdentity)filterContext.HttpContext.User.Identity).Claims
                 .Where(c => c.Type == System.Security.Claims.ClaimTypes.Role)
                 .Select(c => c.Value);

                var hasRoles = userRoles.Select(s => s).Where(s => Roles.Split(',').Contains(s));

                    // Redirect to your "access denied" view here
                if (hasRoles.Count() == 0)
                {
                    filterContext.Result = new RedirectResult("~/Home/Error?message=Access Denied");
                }
            }
        }
    }

}