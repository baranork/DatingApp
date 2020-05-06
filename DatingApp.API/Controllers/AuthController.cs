using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _repo = repo; 
            _config = config;

        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto userForRegisterDto){
            //Validate Request

            userForRegisterDto.Username = userForRegisterDto.Username.ToLower();

            if(await _repo.UserExists(userForRegisterDto.Username)){
                return BadRequest("Username already exists");
            }

            var userToCreate = new User{
                Username = userForRegisterDto.Username
            };

            var createdUser = await _repo.Register(userToCreate, userForRegisterDto.Password);

            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto userForLoginDto){

            var userFromRepo = await _repo.Login(userForLoginDto.Username.ToLower(), userForLoginDto.Password);

            if(userFromRepo == null){
                return Unauthorized();
            }

            //Aca se crean las claims que queremos ponerle a nuestro token. En este caso queremos que en el payload solamente aparezca el id y el nombre de usuario. Ya que, ademas, los datos que se pongan en los claims pueden ser vistos y por eso no tiene que ser informacion explicita ej: mail, password, birthdate, dni, etc
            var claims = new []{
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.Username)
            };

            //Secret Key (Codificada a byte aray)

            //Se levanta la clave de seguridad del appsettings (Normalmente un string de caracteres generados automatiamente)
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));

            //Credenciales para el Token

            //Aca se crean las credenciales necesarias. Utilizando la secret key levantada anteriormente y el tipo de algoritmo de seguridad que se utilizara en el token.
            //El servidor firma el token para despues, cuando sea utilizado por el usuario, sepa que es valido
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            //Token Payload?

            //Aca en el token descriptor se crea un nuevo SecurityTokenDescriptor al que se le pasan los claims que iran a parar al payload del nuestro token. Ademas el expire sera la duracion de uso del token mismo.
            var tokenDescriptor = new SecurityTokenDescriptor{
                Subject = new ClaimsIdentity(claims), //Nuestros claims anteriormente creados
                Expires = DateTime.Now.AddDays(1),  //Duracion del token
                SigningCredentials = creds        //Credenciales
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            //Este sera el token devuelto para el uso del cliente
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return Ok(new {
                token = tokenHandler.WriteToken(token)
            });
        }
    }
}