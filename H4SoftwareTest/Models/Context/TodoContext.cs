using Microsoft.EntityFrameworkCore;

namespace H4SoftwareTest.Models.Context
{
    public partial class TodoContext : DbContext
    {
        public TodoContext() 
        {
        }

        public TodoContext(DbContextOptions<TodoContext> options)
            :base(options) { }


        public virtual DbSet<Cpr> Cprs { get; set; }
        public virtual DbSet<Todolist> Todolists { get; set; }


        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder) 
        {
            IConfigurationRoot configuration = new ConfigurationBuilder()
                .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
                .AddJsonFile("appsettings.json")
                .Build();
            optionsBuilder.UseSqlServer(configuration.GetConnectionString("TodoConnection"));
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Cpr>(entity =>
            {
                entity.ToTable("Cpr");

                entity.Property(e => e.CprNr).HasMaxLength(500);
                entity.Property(e => e.User).HasMaxLength(500);
            });

            modelBuilder.Entity<Todolist>(entity =>
            {
                entity.ToTable("Todolist");

                entity.Property(e => e.Item).HasMaxLength(500);
                entity.Property(e => e.User).HasMaxLength(500);
                entity.Property(e => e.IsAsymmetric);
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);



    }
}
