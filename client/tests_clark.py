from crypt import *
from difflog import *

test_file = 'aaaabbbccc'
test_file_mod = 'aaabbbbccccddd'
test_file_mod2 = 'aaaabbbccc'
test_file_mod3 = 'aaabbfc;helelo'


if __name__ == "__main__":
    (len_pub,pub,len_priv, priv) = create_asym_key_pair()
    diff = diff_log()
    diff.create_diff('clark',priv,test_file)
    diff.create_diff('clark',priv,test_file,test_file_mod)
    diff.create_diff('clark',priv,test_file_mod,test_file_mod2)
    diff.create_diff('clark',priv,test_file_mod2,test_file_mod3)

    f1 = diff.rebuild_file(1)
    f2 = diff.rebuild_file(2)
    f3 = diff.rebuild_file(3)
    f4 = diff.rebuild_file(4)
    f5 = diff.rebuild_file()

    print test_file,f1
    print test_file_mod,f2
    print test_file_mod2,f3
    print test_file_mod3,f4
    print f5


    print diff[0]
