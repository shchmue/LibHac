﻿using System.IO;

namespace LibHac.IO
{
    public class LocalFileSystem : IAttributeFileSystem
    {
        private string BasePath { get; }

        /// <summary>
        /// Opens a directory on local storage as an <see cref="IFileSystem"/>.
        /// The directory will be created if it does not exist.
        /// </summary>
        /// <param name="basePath">The path that will be the root of the <see cref="LocalFileSystem"/>.</param>
        public LocalFileSystem(string basePath)
        {
            BasePath = Path.GetFullPath(basePath);

            if (!Directory.Exists(BasePath))
            {
                Directory.CreateDirectory(BasePath);
            }
        }

        internal string ResolveLocalPath(string path)
        {
            return Path.Combine(BasePath, path.TrimStart('/'));
        }

        public NxFileAttributes GetFileAttributes(string path)
        {
            path = PathTools.Normalize(path);
            return File.GetAttributes(ResolveLocalPath(path)).ToNxAttributes();
        }

        public void SetFileAttributes(string path, NxFileAttributes attributes)
        {
            path = PathTools.Normalize(path);
            string localPath = ResolveLocalPath(path);

            FileAttributes attributesOld = File.GetAttributes(localPath);
            FileAttributes attributesNew = attributesOld.ApplyNxAttributes(attributes);

            File.SetAttributes(localPath, attributesNew);
        }

        public long GetFileSize(string path)
        {
            path = PathTools.Normalize(path);
            var info = new FileInfo(ResolveLocalPath(path));
            return info.Length;
        }

        public void CreateDirectory(string path)
        {
            path = PathTools.Normalize(path);
            Directory.CreateDirectory(ResolveLocalPath(path));
        }

        public void CreateFile(string path, long size, CreateFileOptions options)
        {
            path = PathTools.Normalize(path);
            string localPath = ResolveLocalPath(path);
            string localDir = Path.GetDirectoryName(localPath);

            if (localDir != null) Directory.CreateDirectory(localDir);

            using (FileStream stream = File.Create(localPath))
            {
                stream.SetLength(size);
            }
        }

        public void DeleteDirectory(string path)
        {
            path = PathTools.Normalize(path);

            string resolveLocalPath = ResolveLocalPath(path);
            Directory.Delete(resolveLocalPath);
        }

        public void DeleteFile(string path)
        {
            path = PathTools.Normalize(path);

            string resolveLocalPath = ResolveLocalPath(path);
            File.Delete(resolveLocalPath);
        }

        public IDirectory OpenDirectory(string path, OpenDirectoryMode mode)
        {
            path = PathTools.Normalize(path);

            return new LocalDirectory(this, path, mode);
        }

        public IFile OpenFile(string path, OpenMode mode)
        {
            path = PathTools.Normalize(path);

            string localPath = ResolveLocalPath(path);
            return new LocalFile(localPath, mode);
        }

        public void RenameDirectory(string srcPath, string dstPath)
        {
            srcPath = PathTools.Normalize(srcPath);
            dstPath = PathTools.Normalize(dstPath);

            string srcLocalPath = ResolveLocalPath(srcPath);
            string dstLocalPath = ResolveLocalPath(dstPath);

            string directoryName = Path.GetDirectoryName(dstLocalPath);
            if (directoryName != null) Directory.CreateDirectory(directoryName);
            Directory.Move(srcLocalPath, dstLocalPath);
        }

        public void RenameFile(string srcPath, string dstPath)
        {
            srcPath = PathTools.Normalize(srcPath);
            dstPath = PathTools.Normalize(dstPath);

            string srcLocalPath = ResolveLocalPath(srcPath);
            string dstLocalPath = ResolveLocalPath(dstPath);
            string dstLocalDir = Path.GetDirectoryName(dstLocalPath);

            if (dstLocalDir != null) Directory.CreateDirectory(dstLocalDir);
            File.Move(srcLocalPath, dstLocalPath);
        }

        public bool DirectoryExists(string path)
        {
            path = PathTools.Normalize(path);

            return Directory.Exists(ResolveLocalPath(path));
        }

        public bool FileExists(string path)
        {
            path = PathTools.Normalize(path);

            return File.Exists(ResolveLocalPath(path));
        }

        public DirectoryEntryType GetEntryType(string path)
        {
            path = PathTools.Normalize(path);
            string localPath = ResolveLocalPath(path);

            if (Directory.Exists(localPath))
            {
                return DirectoryEntryType.Directory;
            }

            if (File.Exists(localPath))
            {
                return DirectoryEntryType.File;
            }

            throw new FileNotFoundException(path);
        }

        public void Commit() { }
    }
}
