using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Identity.Client;
using System.Security.Claims;
using System.Threading.Tasks;

namespace RBPoc.Utils
{
    public static class MsalAppBuilder
    {
        /// <summary>
        /// Shared method to create an IConfidentialClientApplication from configuration and attach the application's token cache implementation
        /// </summary>
        /// <returns></returns>
        public static IConfidentialClientApplication BuildConfidentialClientApplication()
        {
            return BuildConfidentialClientApplication(ClaimsPrincipal.Current);
        }

        /// <summary>
        /// Shared method to create an IConfidentialClientApplication from configuration and attach the application's token cache implementation
        /// </summary>
        /// <param name="currentUser">The current ClaimsPrincipal</param>
        public static IConfidentialClientApplication BuildConfidentialClientApplication(ClaimsPrincipal currentUser)
        {
            IConfidentialClientApplication clientapp = ConfidentialClientApplicationBuilder.Create(Globals.ClientId)
                  .WithClientSecret(Globals.ClientSecret)
                  .WithRedirectUri(Globals.RedirectUri)
                  .WithB2CAuthority(Globals.B2CAuthority)
                  .Build();

            MSALPerUserMemoryTokenCache userTokenCache = new MSALPerUserMemoryTokenCache(clientapp.UserTokenCache, currentUser ?? ClaimsPrincipal.Current);
            return clientapp;
        }

        /// <summary>
        /// Common method to remove the cached tokens for the currently signed in user
        /// </summary>
        /// <returns></returns>
        public static async Task ClearUserTokenCache()
        {
            IConfidentialClientApplication clientapp = ConfidentialClientApplicationBuilder.Create(Globals.ClientId)
                .WithB2CAuthority(Globals.B2CAuthority)
                .WithClientSecret(Globals.ClientSecret)
                .WithRedirectUri(Globals.RedirectUri)
                .Build();

            // We only clear the user's tokens.
            MSALPerUserMemoryTokenCache userTokenCache = new MSALPerUserMemoryTokenCache(clientapp.UserTokenCache);
            var userAccounts = await clientapp.GetAccountsAsync();

            foreach (var account in userAccounts)
            {
                //Remove the users from the MSAL's internal cache
                await clientapp.RemoveAsync(account);
            }
            userTokenCache.Clear();

        }
    }
}