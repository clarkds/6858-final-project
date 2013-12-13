import api2

reload(api2)
api2.api_create_user('leo1','111111')
handle = api2.api_create_file('/leo1/t1')
api2.api_fwrite(handle, "kobe")
api2.api_fflush(handle)
api2.api_fclose(handle)

handle = api2.api_fopen('/leo1/t1','r')
print api2.api_fread(handle)