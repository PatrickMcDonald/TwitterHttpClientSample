namespace TwitterHttpClientSampleConsole
{
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading;
    using System.Threading.Tasks;
    using OAuth;

    /// <summary>
    /// Basic DelegatingHandler that creates an OAuth authorization header based on the OAuthBase
    /// class downloaded from http://oauth.net
    /// </summary>
    public class OAuthMessageHandler : DelegatingHandler
    {
        // Obtain these values by creating a Twitter app at http://dev.twitter.com/
        private static string consumerKey = "Enter your consumer key";
        private static string consumerSecret = "Enter your consumer secret";
        private static string token = "Enter your token";
        private static string tokenSecret = "Enter your token secret";

        private OAuthBase oauthBase = new OAuthBase();

        public OAuthMessageHandler(HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Compute OAuth header 
            string normalizedUri;
            string normalizedParameters;

            string signature = this.oauthBase.GenerateSignature(
                request.RequestUri,
                consumerKey,
                consumerSecret,
                token,
                tokenSecret,
                request.Method.Method,
                this.oauthBase.GenerateTimeStamp(),
                this.oauthBase.GenerateNonce(),
                out normalizedUri,
                out normalizedParameters);

            var authHeader = string.Empty;

            request.Headers.Authorization = new AuthenticationHeaderValue("OAuth", authHeader);
            return base.SendAsync(request, cancellationToken);
        }
    }
}