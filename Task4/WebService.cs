using Grapevine.Interfaces.Server;
using Grapevine.Server;
using Grapevine.Server.Attributes;
using Grapevine.Shared;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;

namespace vulnappcore
{
    [RestResource]
    class WebServer
    {
        private string _static_content_directory = "static";
        private MySqlClient msqlc = MySqlClient.GetMySqlClient();
        private static Dictionary<String, String> _tokens_allowed = new Dictionary<string, string>();

        private String GenRandomStr(int length)
        {
            return md5sum_hex(DateTime.Now.ToBinary().ToString() + "fdlkjfhs;ldhgfakjsdgh")[..length];
        }

        private IHttpContext ReturnError(int id, IHttpContext context)
        {
            context.Response.Redirect($"/{id}.jpg");
            context.Response.SendResponse("");
            return context;
        }

        private String securehash(String data)
        {
            var md = MD5.Create();
            byte[] sdata = Encoding.UTF8.GetBytes(data);
            byte[] r = md.ComputeHash(sdata);

            string binhash = Encoding.UTF8.GetString(r);

            binhash = new Regex("[^a-zA-Z0-9!@#$%^&*()_\\-'\"\\/;\\\\]").Replace(binhash, "Z");
            Console.WriteLine($"Hashed '{data}' as '{binhash}' ('{md5sum_hex(data)}')");
            return binhash;
        }

        private String md5sum_hex(String data)
        {
            var md = MD5.Create();
            byte[] sdata = Encoding.UTF8.GetBytes(data);
            byte[] r = md.ComputeHash(sdata);
            string result = "";
            foreach (var c in r)
            {
                result += c.ToString("X2").ToLower();
            }

            return result;
        }

        private String base64(String data) => Convert.ToBase64String(Encoding.UTF8.GetBytes(data));

        public static void Log(String what)
        {
            File.AppendAllText("app.log", what + "\r\n");
            Console.WriteLine(what);
        }

        [RestRoute(PathInfo = "/login")]
        public IHttpContext Login(IHttpContext context)
        {
            try
            {
                if (context.Request.HttpMethod == HttpMethod.GET)
                {
                    context.Response.SendResponse(File.ReadAllText(_static_content_directory + "/login.html"));
                    return context;
                }
                else if (context.Request.HttpMethod != HttpMethod.POST)
                {
                    return ReturnError(405, context);
                }

                // Got POST request with login info
                String payload = HttpUtility.UrlDecode(context.Request.Payload);
                string[] args = payload.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries);
                if (args.Length != 2)
                {
                    return ReturnError(500, context);
                }

                String usr = "", pwd = "";
                foreach (var ci in args)
                {
                    if (ci.StartsWith("username="))
                    {
                        usr = ci.Replace("username=", "");
                    }

                    if (ci.StartsWith("password="))
                    {
                        pwd = ci.Replace("password=", "");
                    }
                }

                String pwdhash = securehash(pwd);
                String request_string = $"SELECT * FROM test WHERE password='{pwdhash}' AND email='{usr}'";
                var mysql_response = msqlc.ExecuteCustomQueryWithData(request_string, new[] { "email" });
                if (mysql_response["email"].Count != 0)
                {
                    String _rand_token = GenRandomStr(10);
                    _tokens_allowed.Add(_rand_token, mysql_response["email"][0]);
                    String _r = base64($"{{\"user\": \"{mysql_response["email"][0]}\", \"pass\": \"{pwd}\", \"token\": \"{_rand_token}\"}}");
                    context.Response.AppendCookie(new Cookie("login", _r));
                    context.Response.Redirect("/posts");
                    context.Response.SendResponse("");
                }
                else
                {
                    return ReturnError(401, context);
                }
            }
            catch
            {
                return ReturnError(500, context);
            }

            return context;
        }

        [RestRoute(PathInfo = "/logout")]
        public IHttpContext Logout(IHttpContext context)
        {
            context.Response.SetCookie(new Cookie("login", "") { Expires = DateTime.MinValue });
            context.Response.Redirect("/login");
            context.Response.SendResponse("");
            return context;
        }

        [RestRoute(PathInfo = "/register")]
        public IHttpContext Register(IHttpContext context)
        {
            try
            {
                if (context.Request.Cookies.Count != 0)
                {
                    context.Response.Redirect("/posts");
                    context.Response.SendResponse("");
                    return context;
                }

                if (context.Request.HttpMethod == HttpMethod.GET)
                {
                    // Just visited, return login page
                    context.Response.SendResponse(File.ReadAllText(_static_content_directory + "/register.html"));
                    return context;
                }
                else if (context.Request.HttpMethod != HttpMethod.POST)
                {
                    return ReturnError(405, context);
                }

                // Got POST request with reg info
                String payload = HttpUtility.UrlDecode(context.Request.Payload);
                string[] args = payload.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries);
                if (args.Length != 2 || payload.Contains("'") || payload.Contains("\""))
                {
                    return ReturnError(400, context);
                }

                String usr = "", pwd = "";
                foreach (var ci in args)
                {
                    if (ci.StartsWith("username="))
                    {
                        usr = ci.Replace("username=", "");
                        if (!new Regex(@"^[0-9a-zA-Z_]+\@[a-zA-Z0-9_]+\.[a-zA-Z]{2,}$").IsMatch(usr))
                        {
                            context.Response.SendResponse("<h1>Your email is invalid!</h1>");
                            return context;
                        }
                    }

                    if (ci.StartsWith("password="))
                    {
                        pwd = ci.Replace("password=", "");
                    }
                }

                if (msqlc.ExecuteCustomQueryWithData($"SELECT email FROM test WHERE email='{usr}'", new[] { "email" })["email"].Count != 0)
                {
                    context.Response.SendResponse("<h1>This email is already registered!</h1>");
                    return context;
                }

                String pwdhash = securehash(pwd);
                msqlc.ExecuteCustomQuery($"INSERT INTO test (email, password) VALUES('{usr}', '{pwdhash.Replace("\\", "")}')");
                context.Response.Redirect("/login");
                context.Response.SendResponse("");
            }
            catch
            {
                return ReturnError(500, context);
            }

            return context;
        }

        [RestRoute(PathInfo = "/posts")]
        public IHttpContext Posts(IHttpContext context)
        {
            try
            {
                if (context.Request.Cookies.Count == 0)
                {
                    context.Response.SendResponse("<html><head><meta http-equiv=\"refresh\" content=\"3;url=/login\" /></head><body><h1>Please login or register first!</h1></body></html>");
                    return context;
                }

                string usr, token;
                try
                {
                    var rdic = JsonConvert.DeserializeObject<Dictionary<String, String>>(Encoding.UTF8.GetString(Convert.FromBase64String(context.Request.Cookies[0].Value)));
                    usr = rdic["user"];
                    token = rdic["token"];
                }
                catch
                {
                    return ReturnError(403, context);
                }
                
                if (!_tokens_allowed.ContainsKey(token) || _tokens_allowed[token] != usr)
                {
                    context.Response.SendResponse("<html><head><meta http-equiv=\"refresh\" content=\"3;url=/logout\" /></head><body><h1>Your token is invalid!</h1></body></html>");
                    return context;
                }

                var _r = msqlc.ExecuteCustomQueryWithData($"SELECT author,header FROM posts WHERE email='{usr}' OR private=0;", new[] { "author", "header" });
                if (_r["author"].Count is 0)
                {
                    context.Response.SendResponse("<h1>No posts available!</h1>");
                    return context;
                }

                String resp = $"<h1>Here are posts available ({_r["author"].Count})</h1>%P%<br /><br /><br /><br /><a href=\"/logout\">Logout</a>";

                for (int i = 0; i < _r["author"].Count; i++)
                {
                    var _a = _r["author"][i];
                    var _h = _r["header"][i];
                    resp = resp.Replace("%P%", $"<h2>{_h}</h2>By <i>{_a}</i><br />%P%");
                }

                context.Response.SendResponse(resp.Replace("%P%", ""));
                return context;
            }
            catch
            {
                return ReturnError(500, context);
            }
        }

        [RestRoute(HttpMethod = HttpMethod.GET, PathInfo = "/")]
        public IHttpContext RedirectToMain(IHttpContext context)
        {
            context.Response.Redirect("/description.html");
            context.Response.SendResponse("");
            return context;
        }

        [RestRoute(HttpMethod = HttpMethod.GET)]
        public IHttpContext FailbackGet(IHttpContext context)
        {
            try
            {
                if (string.IsNullOrEmpty(context.Request.PathInfo))
                {
                    return RedirectToMain(context);
                }

                byte[] resp = null;
                try
                {
                    if (context.Request.PathInfo.ToLower().EndsWith("html"))
                    {
                        string dat = File.ReadAllText(_static_content_directory + context.Request.PathInfo);
                        context.Response.SendResponse(dat);
                        return context;
                    }

                    if (context.Request.PathInfo.ToLower().StartsWith("/generate_"))
                    {
                        return ReturnError(int.Parse(context.Request.PathInfo.Replace("/generate_", "")), context);
                    }

                    resp = File.ReadAllBytes(_static_content_directory + context.Request.PathInfo);
                    Log($"Returned {new FileInfo(_static_content_directory + context.Request.PathInfo).Length} bytes to {context.Request.RemoteEndPoint.Address} ({context.Request.PathInfo} requested)");
                }
                catch
                {
                    Log($"Requested {context.Request.PathInfo}, but ran into error");
                }

                if (resp != null)
                {
                    context.Response.SendResponse(resp);
                }
                else
                {
                    {
                        return ReturnError(404, context);
                    }
                }
            }
            catch
            {
                return ReturnError(418, context);
            }

            return context;
        }
    }
}
