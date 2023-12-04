## 1. Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationHandler 
验证是否登录（Cookie是否存在）  

## 2. Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectHandler 
没有登录，发起身份认证 HandleChallengeAsync();  

### 2.1 构建 OpenIdConnectMessage、AuthenticationProperties
message就是调用授权的一些参数的封装，properties则是用来存储客户端的一些参数（code verifier、CorrelationId等）。  
构建调用授权的一些参数：client_id、client_secret、scope、redirect_uri、response_mode等；  
其中构建message时的两个概念解释一下：  
```
"Nonce": "nonce 是一个用于防止重放攻击的参数。nonce 的全称是 "Number Used Once"，它是一个一次性的随机值，用于确保在同一时间内相同的请求不会被重复执行。"

"PKCE": "PKCE（Proof Key for Code Exchange）是一种用于增强 OAuth 2.0 授权流程安全性的机制。它主要用于在使用授权码授权流程（Authorization Code Flow）时防止授权码被中间人攻击截取的情况。
在标准的授权码授权流程中，客户端在获取访问令牌之前先获得一个授权码，然后再用该授权码去交换访问令牌。而 PKCE 的引入是为了解决在这个授权码交换过程中的安全问题。  
PKCE 的主要思想是，客户端在开始认证流程前，生成一个随机的 code verifier，并计算它的哈希值，称之为 code challenge。客户端在认证请求中包含 code challenge，并在后续的令牌请求中再次提供原始的 code verifier。授权服务器在颁发授权码时验证 code challenge 和 code verifier 是否匹配，从而确保令牌请求的合法性。
通过 PKCE，即使攻击者截获了授权码，由于缺乏对应的 code verifier，他们无法有效地使用该授权码进行访问令牌的获取。这种机制增加了在认证流程中的安全性，特别是在移动应用和桌面应用等容易受到中间人攻击的环境中。
总的来说，PKCE 是一种为 OAuth 2.0 提供额外安全性的机制，尤其在授权码授权流程中使用时，可以有效防范某些攻击手段。"
```
如果用到Nonce需要写入Cookie（.AspNetCore.OpenIdConnect.Nonce.xxxxx）；  
本地会生成一个CorrelationId的Cookie（.AspNetCore.Correlation.xxxxx）；  
RemoteAuthenticationHandler.GenerateCorrelationId(AuthenticationProperties properties)；  
properties又会通过message的state参数进行传递，而不是保存在内存中。  

```chsarp
message.State = Options.StateDataFormat.Protect(properties);
```

### 2.2 触发 OnRedirectToIdentityProvider 事件
然后会触发 await Events.RedirectToIdentityProvider(redirectContext);  
如果在事件中将 redirectContext.Handled 设置为true就会直接返回。

### 2.3 发起授权请求
发起授权有两种方式`AuthenticationMethod`：一种是RedirectGet，一种是FormPost;  
如果用FormPost，客户端会返回一段html中包含form表单的代码，由js提交form表单到IdentityServer的`/connect/authorize`，由于Cookie的SameSite限制，每次都需要重新登录;  
如果用RedirectGet的方式，通过URL跳转，同时携带Cookie。 

## 3. 服务端处理授权请求
### 3.1 接收到授权请求 /connect/authorize
服务端接收到请求后，验证是否已经登录；  
如果没有登录，就会跳转到`/Account/Login`。

### 3.2 服务端登录成功后回调客户端
登录成功后会跳转到``
如果 response mode 是 query|fragment，则会通过跳转的方式回到客户端（纯前端的授权码模式）；  
如果 response mode 是 form_post，则会返回一个 html界面，并用js自动post回调地址`/signin-oidc`（AspNetCore中OpenIdConnect）。 

## 4. Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectHandler
处理回调请求 HandleRemoteAuthenticateAsync()  
### 4.1 通过参数构建 OpenIdConnectMessage
有Get（授权码模式）或者Post（混合模式、简化模式）两种方式。
### 4.2 通过message构建properties
```
properties = Options.StateDataFormat.Unprotect(message.State);
```
### 4.3 验证 CorrelationId
这就是为什么Correlation的Cookie的 SameSite=Lax 在这一步不会携带的原因，因为是跨站POST请求，所以会提示`.AspNetCore.Correlation.xxxxx Cookie 不存在`； 

```csharp
if (!ValidateCorrelationId(properties))
{
    return HandleRequestResult.Fail("Correlation failed.", properties);
}
```

所以使用OpenIdConnect接入IdentityServer的正确配置或许应该是：  

```csharp
builder.Services
    .AddAuthentication()
    ...// 此处省略一万行
    .AddOpenIdConnect("oidc", options =>
{
    options.CorrelationCookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Unspecified;
    options.CorrelationCookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.None;
    options.NonceCookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Unspecified;
    options.NonceCookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.None;
});
```

### 4.4 验证返回的 id_token
...

### 4.5 通过code取access_token
验证通过后就开始解析参数，里面包含了code跟id_token，拿到code在跟服务端换取access_token  

### 4.6 保存tokens
如果设置OpenIdConnectOptions时，SaveTokens设置成了true，就会将token保存，以便在代码中可以通过`
HttpContext.GetTokensAsync("id_token")`获取。

### 4.7 获取｜构建用户信息
...

### 5. 一些链接
[1. OpenIdConnectMessage 源码位置](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet)
