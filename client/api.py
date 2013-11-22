init(username)
destroy()

iterator opendir(path)
readdir(iterator)
closedir(iterator)

handle (index/which buffer) fopen(path)
fseek(handle, offset, whence)
ftell(handle)
fwrite(binary, numbytes, handle)
binary fread(n, handle)
fclose(handle)

mkdir(path)
chdir(path)

struct fstat(path) - search for key in our table
list of users & permisions list_permissions(path)
grant(path, user, R/W)
revoke(path, user)
mv(oldpath, newpath)
rm(path)
