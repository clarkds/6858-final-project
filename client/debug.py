import api2
import time
import sys

reload(api2)
api2.api_create_user('leo1','111111')
handle = api2.api_create_file('/leo1/t1')
api2.api_fwrite(handle, "kobe")
api2.api_fflush(handle)
api2.api_fclose(handle)

handle = api2.api_fopen('/leo1/t1','r')
print api2.api_fread(handle)
api2.api_fclose(handle)
handle = api2.api_fopen('/leo1/t1','r')
print api2.api_fread(handle)
api2.api_fclose(handle)

api2.api_mkdir('/leo1/twinkies')
handle = api2.api_fopen('/leo1/twinkies/celtics','w')
api2.api_fwrite(handle, "tab complete")
api2.api_fflush(handle)
api2.api_fclose(handle)

api2.api_logout()

time.sleep(1)

api2.api_login('leo1','111111')

handle = api2.api_fopen('/leo1/t1','r')
text1 = api2.api_fread(handle)
api2.api_fclose(handle)

handle2 = api2.api_fopen('/leo1/twinkies/celtics','r')
text2 = api2.api_fread(handle2)
api2.api_fclose(handle2)

print "text1: ", text1
print "text2: ", text2

handle = api2.api_create_file('/leo1/t2')
api2.api_fwrite(handle, "kobe. celtics suck")
api2.api_fflush(handle)
api2.api_fclose(handle)

handle = api2.api_create_file('/leo1/t3')
api2.api_fwrite(handle, "lakers > celtics")
api2.api_fflush(handle)
api2.api_fclose(handle)

handle = api2.api_create_file('/leo1/t4')
api2.api_fwrite(handle, "dd")
api2.api_fflush(handle)
api2.api_fclose(handle)

#print api2.api_list_dir('/leo1')
print api2.api_rm('/leo1/t4')

print api2.api_list_dir('/leo1')

api2.api_mv('/leo1/t2', '/leo1/twinkies/t2')
list1 = api2.api_list_dir('/leo1')
list2 = api2.api_list_dir('/leo1/twinkies')
print "list1", list1
print "list2", list2

api2.api_logout()
api2.api_create_user('leo2','111111')
api2.api_logout()
api2.api_login("leo1", "111111")
dir_handle = api2.api_opendir("/leo1")
api2.api_set_permissions(dir_handle, ["leo2"], [])
api2.api_fflush(dir_handle)
api2.api_fclose(dir_handle)
handle = api2.api_fopen("/leo1/t3", "w")
api2.api_set_permissions(handle, ["leo2"], [])
#### does not flush
api2.api_fflush(handle)
api2.api_fclose(handle)
api2.api_logout()

api2.api_login("leo2", "111111")
handle = api2.api_fopen("/leo1/t3", "r")
