using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseAPIController
    {
        private readonly DataContext _conxext;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext conxext, ITokenService tokenService)
        {
            _conxext = conxext;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto){

            if(await UserExists(registerDto.Username)) return BadRequest("Username is taken");
            
            using var hmac = new HMACSHA512();

            var user = new AppUser{
                UserName =registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };

            _conxext.Users.Add(user);

            await _conxext.SaveChangesAsync();
            
            return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
    
            };
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto){
            var user = await _conxext.Users.SingleOrDefaultAsync(u=>u.UserName == loginDto.Username);

            if(user ==null) return Unauthorized("Invalid Username");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for(int i =0; i<computedHash.Length;i++){
                if(computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
            }

            return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)

            };

        }
        private async Task<bool> UserExists(string username){
            return await _conxext.Users.AnyAsync(u=>u.UserName == username.ToLower());
        }
        
    }
}