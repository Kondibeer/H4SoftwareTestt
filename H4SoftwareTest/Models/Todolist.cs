namespace H4SoftwareTest.Models
{
    public class Todolist
    {
        public int Id { get; set; }
        public string User { get; set; } = null!;
        public string Item { get; set; } = null!;
        public bool IsAsymmetric { get; set; }
    }
}
