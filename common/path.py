import string

# sanitizes the path (removes duplicate slashes, trailing slashes)
# ex: sanitize_path('//a/b/c//d//') => ('/a/b/c/d', ['', 'a', 'b', 'c', 'd'])
# For an absolute path, the path_parts[0]='' and path_parts[1]=user
def sanitize_path(path):
	path_parts = path.split('/')
	path_parts = [path_parts[0]] + filter(None, path_parts[1:])  # remove empty strings from list
	clean_path = string.join(path_parts,'/')
	return clean_path

def resolve_path(path):
	path = sanitize_path(path)
	sub_path = path.split('/')
	new_path = ""
	for i in sub_path:
		if i == '..':
			new_path = get_parent_directory(new_path)
		else:
			new_path = new_path + '/' + i
	return sanitize_path(new_path)

def get_absolute_path(current_dir, path):
	path = sanitize_path(path)
	if path[0] == '/':
		return get_absolute_path('/', path[1:])
	else:
		return resolve_path(current_dir + path)
		
def get_parent_directory(path):
	sub_path = path.split('/')
	sub_path = sub_path[0:len(sub_path) - 1]
	sub_path = "/".join(sub_path)
	return sub_path

def get_metafile_path(path):
	sub_path = get_parent_directory(path)
	meta_path = sub_path + '/.meta_' + path.split('/')[-1]
	return meta_path

def get_logfile_path(path):
	sub_path = get_parent_directory(path)
	log_path = sub_path + '/.log_' + path.split('/')[-1]
	return log_path

def get_original_path(path):
	sub_path = get_parent_directory(path)
	log_path = sub_path + '/.orig_' + path.split('/')[-1]
	return log_path
	
def split_path(path):
	parts = path.split("/")
	filename = parts[-1]
	if len(parts) > 1:
		parent = string.join(parts[0:-1], "/")
	else:
		parent = None
	return (parent, filename)
	
def strip_meta(key):
	key_list = key.split('/')
	if key_list[-1].startswith('.meta_'):
		key_list[-1] = key_list[-1][len('.meta_'):]
	key = string.join(key_list, '/')
	return key