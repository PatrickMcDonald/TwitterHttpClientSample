namespace TwitterHttpClientSampleConsole
{
    using System;
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

            string timeStamp = this.oauthBase.GenerateTimeStamp();
            string nonce = this.oauthBase.GenerateNonce();

            string signature = this.oauthBase.GenerateSignature(
                request.RequestUri,
                consumerKey,
                consumerSecret,
                token,
                tokenSecret,
                request.Method.Method,
                timeStamp,
                nonce,
                out normalizedUri,
                out normalizedParameters);

            var authHeader = GenerateAuthHeader(consumerKey, token, timeStamp, nonce, signature, request.Method.Method);

            request.Headers.Authorization = new AuthenticationHeaderValue("OAuth", authHeader);
            return base.SendAsync(request, cancellationToken);
        }

        private static string GenerateAuthHeader(string consumerKey, string token, string timeStamp, string nonce, string signature, string signatureMethod)
        {
            string authHeader;
            authHeader = string.Format(
                "oauth_consumer_key=\"{0}\", oauth_nonce=\"{1}\", oauth_signature=\"{2}\", oauth_signature_method=\"{3}\", oauth_timestamp=\"{4}\", oauth_version=\"{5}\"",
                consumerKey,
                nonce,
                Uri.EscapeDataString(signature),
                signatureMethod,
                timeStamp,
                OAuthBase.OAuthVersion);

            if (string.IsNullOrEmpty(token))
            {
                return authHeader;
            }

            return authHeader + string.Format(", oauth_token=\"{0}\"", token);
        }
    }
}