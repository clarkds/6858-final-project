def get_absolute_path(current_dir, path):
	if path[0] == '/':
		return path
	else:
		absolute_path = current_dir
		sub_paths = path.split('/')
		for i in range(len(sub_paths)):
			if sub_path[i] == '..':
				absolute_path = get_parent_directory(absolute_path)
			else:
				absolute_path = absolute_path + '/' + sub_path[i]
	return absolute_path

def sanitize_path():
	pass

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
