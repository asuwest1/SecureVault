namespace SecureVault.Core.Entities;

public class Folder
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public Guid? ParentFolderId { get; set; }
    public int Depth { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public Folder? ParentFolder { get; set; }
    public ICollection<Folder> Children { get; set; } = new List<Folder>();
    public ICollection<Secret> Secrets { get; set; } = new List<Secret>();
    public ICollection<FolderAcl> FolderAcls { get; set; } = new List<FolderAcl>();
}
