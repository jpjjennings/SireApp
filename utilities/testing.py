from datetime import datetime


current_time = datetime.now()
time_test = datetime.strftime(current_time, "%Y-%m-%d %H:%M:%S")
print(time_test)