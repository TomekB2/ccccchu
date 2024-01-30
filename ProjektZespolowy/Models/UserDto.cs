namespace ProjektZespolowy.Models
{
    public class UserDto
    {
        public required string login { get; set; }
        public required string password { get; set; }
        public required string email { get; set; }
    }
}
