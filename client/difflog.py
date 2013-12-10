import diff_match_patch as diff
import crypt
import datetime

    
    
class diff_log(list):
    """ class for the entire diff log of a file
    """
    
    def __init__(self,csk,filepassw):
        ## stores the file name, where it was created, owner of the file
        ## stores the diff_log of the file as an instance array of diff_obj
        list.__init__(self)
        self.csk=csk
        self.filepassw=filepassw
        self.perm=[]
        self.perm.append([])
        self.perm.append([])
        
    def _generate_patch(self, orig_file, mod_file):
        #creates the patch for entry into the diff log.
        # parse last edit in the file for edit_number
        dmp = diff.diff_match_patch()
        dmp.Diff_Timeout = 0   #no timeout
        diffs = dmp.diff_main(orig_file, mod_file)
        patches = dmp.patch_make(orig_file, diffs)
        text_patches = dmp.patch_toText(patches)
        return text_patches
    
    def update_secrets(csk,filepassw):
    	self.csk=csk
    	self.filepassw=filepassw
    	
    def update_perm(self,readperm,writeperm):
    	self.perm[0]=readperm
    	self.perm[1]=writeperm
        
    def create_diff(self, user, user_SK, orig_file, mod_file = None, comments = None):
        new_diff = diff_obj()
        new_diff.user = user
        new_diff.edit_number = self.len()
        if comments != None:
        	new_diff.comments = comments
        if mod_file == None:
            new_diff.patch = self._generate_patch('', orig_file)
        else:
            new_diff.patch = self._generate_patch(orig_file, mod_file)
        new_diff.signature = crypt.generate_dig_sig(user_SK, new_diff.patch)[1]
        new_diff.timestamp = datetime.now()
        new_diff.freeze()
        self.append(new_diff)
        
    def rebuild_file(self, index_number =  None):
    	if index_number ==None:
    		index_number=self.len()-1
        file = ''
        dmp = diff.diff_match_patch()
        dmp.Diff_Timeout = 0   #no timeout
        for i in range(index_number):
            patch = dmp.patch_fromText(self._data[i])
            file = dmp.patch_apply(patch, file)
        return file

        
class FrozenClass(object):
    __isfrozen = False  
    def __setattr__(self, key, value):
        if self.__isfrozen:
            raise TypeError( "%r is a frozen class" % self)
        object.__setattr__(self, key, value)
            
    def freeze(self):
        self.__isfrozen = True
    
class diff_obj(FrozenClass):
    """ class for an diff entry into a log file, and the methods to create it
diff structure:  
    DET(username) + enc(user_sk, file_diff)
    file_diff = edit_number, timestamp, comments, patch
    """
    
    def __init__(self):
        self.user = None                    #the user that made the edit
        self.signature = None       
        self.edit_number = None             
        self.timestamp = None
        self.comments = None                #optional comments made by user
        self.patch = None
        
    def __str__(self):
        return 'hithere'
        
        '''"{self.user} edited the file on {self.timestamp}
           it was edit number: {self.edit_number}
           comments: {self.comments}".format(self=self)'''
           
    