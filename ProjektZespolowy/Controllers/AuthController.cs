using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ProjektZespolowy.Models;
using Npgsql;
using System.Collections.Generic;
using Newtonsoft.Json;
using Dapper;
using System.Data;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace ProjektZespolowy.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto request)
        {
            ErrorMessage ms = new ErrorMessage();
            if (request.password == string.Empty)
            {
                ms.Message = "Haslo nie moze byc puste";
                return BadRequest(ms);
            }
            if (request.login == string.Empty)
            {
                ms.Message = "Login nie moze byc pusty";
                return BadRequest(ms);
            }
            if (request.email == string.Empty)
            {
                ms.Message = "Mail nie moze byc pusty";
                return BadRequest(ms);
            }

            string passwordhash = BCrypt.Net.BCrypt.HashPassword(request.password);

            try
            {
                NpgsqlConnection conn = new NpgsqlConnection(_configuration.GetConnectionString("Post").ToString());
                conn.Open();
                conn.Execute($"INSERT INTO public.\"user\"\r\n(email, login, \"password\")\r\nVALUES('{request.email}', '{request.login}', '{passwordhash}');");
                conn.Close();

            }
            catch (Exception e)
            {
                if (((Npgsql.PostgresException)e).ConstraintName == "user_unique")
                {
                    ms.Message = "Podano istniejace dane";
                    return BadRequest(ms);
                }
                else
                {
                    ms.Message = e.Message;
                    return BadRequest(ms);
                }
            }

            return NoContent();
        }
        [HttpPost("login")]
        public ActionResult<User> login(LoginDto request)
        {
            ErrorMessage ms = new ErrorMessage();
            var jwtOptions = _configuration.GetSection("JwtOptions").Get<JwtOptions>();
            if (request.password == string.Empty)
            {
                ms.Message = "Haslo nie moze byc puste";
                return BadRequest(ms);
            }
            if (request.login == string.Empty)
            {
                ms.Message = "Login nie moze byc pusty";
                return BadRequest(ms);
            }
            string passwordhash = BCrypt.Net.BCrypt.HashPassword(request.password);
            try
            {
                NpgsqlConnection conn = new NpgsqlConnection(_configuration.GetConnectionString("Post").ToString());
                conn.Open();
                NpgsqlDataAdapter adapter = new NpgsqlDataAdapter($"SELECT login, \"password\"\r\nFROM public.\"user\" where login=\'{request.login}\'", conn);
                DataTable dataTable = new DataTable();
                adapter.Fill(dataTable);
                if (dataTable.Rows.Count == 0)
                {
                    ms.Message = "Nie znaleziono uzytkownika";
                    return BadRequest(ms);
                }
                else if (dataTable.Rows.Count == 1)
                {
                    User user = new User();
                    foreach (DataRow row in dataTable.Rows)
                    {
                        user.password = row["password"].ToString();
                        user.login = row["login"].ToString();
                    }
                    if (!BCrypt.Net.BCrypt.Verify(request.password, user.password))
                    {
                        ms.Message = "Niepoprawne haslo";
                        return BadRequest(ms);
                    }
                    else
                    {
                        JwtToken tk = new JwtToken();
                        tk.Token = "Bearer " + CreateAccessToken(jwtOptions, user.login, new TimeSpan(1));
                        return Ok(tk);
                    }
                }
                else
                {
                    ms.Message = "Nieokreslony blad";
                    return BadRequest(ms);
                }
            }
            catch (Exception e)
            {
                ms.Message = e.Message;
                return BadRequest(ms);
            }
        }
        private static string CreateAccessToken(JwtOptions jwtOptions, string username, TimeSpan expiration)
        {
            var keyBytes = Encoding.UTF8.GetBytes(jwtOptions.SigningKey);
            var symmetricKey = new SymmetricSecurityKey(keyBytes);

            var signingCredentials = new SigningCredentials(
                symmetricKey,
                SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>()
            {
                new Claim("sub", username),
                new Claim("name", username),
                new Claim("aud", jwtOptions.Audience)
            };

            var token = new JwtSecurityToken(
                issuer: jwtOptions.Issuer,
                audience: jwtOptions.Audience,
                claims: claims,
                expires: DateTime.Now.Add(expiration),
                signingCredentials: signingCredentials);

            var rawToken = new JwtSecurityTokenHandler().WriteToken(token);
            return rawToken;
        }
    }
    public class JwtToken
    {
        public string? Token { get; set; }
    }
    public class ErrorMessage
    {
        public string? Message { get; set; }
    }
    public record JwtOptions(
    string Issuer,
    string Audience,
    string SigningKey,
    int ExpirationSeconds);
}
