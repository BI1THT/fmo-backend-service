namespace Sas.Auth;

/// <summary>
/// Authentication pipeline entry point. Implemented by <see cref="HttpAuthHandler"/>.
/// </summary>
public interface IAuthHandler
{
    AuthResult Process(string username, string password, string requestId);
}
