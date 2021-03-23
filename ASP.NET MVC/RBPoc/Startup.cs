using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.Owin;
using RBPoc.Utils;
using System.Net.Http.Headers;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

[assembly: OwinStartup(typeof(RBPoc.Startup))]

namespace RBPoc
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }

        public void ConfigureAuth(IAppBuilder app)
        {
            // Required for Azure webapps, as by default they force TLS 1.2 and this project attempts 1.0
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                // ASP.NET web host compatible cookie manager
                CookieManager = new SystemWebChunkingCookieManager()
            });

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    // Generate the metadata address using the tenant and policy information
                    MetadataAddress = String.Format(Globals.WellKnownMetadata, Globals.Tenant, Globals.DefaultPolicy),

                    // These are standard OpenID Connect parameters, with values pulled from web.config
                    ClientId = Globals.ClientId,
                    RedirectUri = Globals.RedirectUri,
                    PostLogoutRedirectUri = Globals.RedirectUri,

                    // Specify the callbacks for each type of notifications
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        RedirectToIdentityProvider = OnRedirectToIdentityProvider,
                        AuthorizationCodeReceived = OnAuthorizationCodeReceived,
                        AuthenticationFailed = OnAuthenticationFailed,

                    },

                    // Specify the claim type that specifies the Name property.
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        NameClaimType = "name",
                        ValidateIssuer = false,

                    },

                    // Specify the scope by appending all of the scopes requested into one string (separated by a blank space)
                    Scope = $"openid profile offline_access {Globals.ReadTasksScope} {Globals.WriteTasksScope}",

                    // ASP.NET web host compatible cookie manager
                    CookieManager = new SystemWebCookieManager()
                }
            );
        }

        /*
         *  On each call to Azure AD B2C, check if a policy (e.g. the profile edit or password reset policy) has been specified in the OWIN context.
         *  If so, use that policy when making the call. Also, don't request a code (since it won't be needed).
         */
        private Task OnRedirectToIdentityProvider(RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            var policy = notification.OwinContext.Get<string>("Policy");

            if (!string.IsNullOrEmpty(policy) && !policy.Equals(Globals.DefaultPolicy))
            {
                notification.ProtocolMessage.Scope = OpenIdConnectScope.OpenId;
                notification.ProtocolMessage.ResponseType = OpenIdConnectResponseType.IdToken;
                notification.ProtocolMessage.IssuerAddress = notification.ProtocolMessage.IssuerAddress.ToLower().Replace(Globals.DefaultPolicy.ToLower(), policy.ToLower());
            }

            return Task.FromResult(0);
        }

        /*
         * Catch any failures received by the authentication middleware and handle appropriately
         */
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> notification)
        {
            notification.HandleResponse();

            // Handle the error code that Azure AD B2C throws when trying to reset a password from the login page
            // because password reset is not supported by a "sign-up or sign-in policy"
            if (notification.ProtocolMessage.ErrorDescription != null && notification.ProtocolMessage.ErrorDescription.Contains("AADB2C90118"))
            {
                // If the user clicked the reset password link, redirect to the reset password route
                notification.Response.Redirect("/Account/ResetPassword");
            }
            else if (notification.Exception.Message == "access_denied")
            {
                notification.Response.Redirect("/");
            }
            else
            {
                notification.Response.Redirect("/Home/Error?message=" + notification.Exception.Message);
            }

            return Task.FromResult(0);
        }

        /*
         * Callback function when an authorization code is received
         */
        private async Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedNotification notification)
        {
            try
            {
                IConfidentialClientApplication confidentialClient = MsalAppBuilder.BuildConfidentialClientApplication(new ClaimsPrincipal(notification.AuthenticationTicket.Identity));

                // Upon successful sign in, get & cache a token using MSAL
                AuthenticationResult result = await confidentialClient.AcquireTokenByAuthorizationCode(Globals.Scopes, notification.Code).ExecuteAsync();
                string token = result.AccessToken;

                using (var client = new HttpClient())
                {

                    string tokenURL = "https://login.microsoftonline.com/skrnd.onmicrosoft.com/oauth2/v2.0/token";

                    var requestContent = new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("grant_type", "client_credentials"),
                        new KeyValuePair<string, string>("client_id", Globals.ClientId),
                        new KeyValuePair<string, string>("scope", "https://graph.microsoft.com/.default"),
                        new KeyValuePair<string, string>("client_secret", Globals.ClientSecret)
                    });


                    var response1 = await client.PostAsync(tokenURL, requestContent);
                    var responseContent = await response1.Content.ReadAsStringAsync();

                    var tokenObj = JObject.Parse(responseContent);
                    JToken accessToke = tokenObj.GetValue("access_token");
                    string accessToken = tokenObj.GetValue("access_token").Value<string>();






                    string requestUrl = $"https://graph.microsoft.com/v1.0/users/{notification.JwtSecurityToken.Subject}/memberOf?$select=displayName";

                    HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, requestUrl);
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                    HttpResponseMessage response = await client.SendAsync(request);
                    var responseString = await response.Content.ReadAsStringAsync();

                    var json = JObject.Parse(responseString);

                    foreach (var group in json["value"])
                        notification.AuthenticationTicket.Identity.AddClaim(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, group["displayName"].ToString(), System.Security.Claims.ClaimValueTypes.String, "Graph"));

                    //TODO: Handle paging. 
                    // https://developer.microsoft.com/en-us/graph/docs/concepts/paging
                    // If the user is a member of more than 100 groups, 
                    // you'll need to retrieve the next page of results.
                }


                //TODO - Approach 1
                // Get the Roles information from the JWT token. We can create a cutom attribute in the AD B2C directory and store the role information for the user. During the user sign-in we can include the custom attribute in the JWT token.

                //TODO - Approach 2
                //Get the user id from the JWT token, send the userid to AD B2C directory using Graph API to get the groups associated with the user. In this approach we need to create groups in the AD B2C Directory and assign groups to the user. here we can consider the group as Role.

                //TODO: Using any one of the approach, we can get the role information. Then, we can include the role claim details in the AuthenticationTicket.Identity

                //Example to add a role claim in the AuthenticationTicket.Identity
                //notification.AuthenticationTicket.Identity.AddClaim(new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, "Administrator", System.Security.Claims.ClaimValueTypes.String, "Graph"));

            }
            catch (Exception ex)
            {
                throw new HttpResponseException(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.BadRequest,
                    ReasonPhrase = $"Unable to get authorization code {ex.Message}."
                });
            }
        }
    }
}