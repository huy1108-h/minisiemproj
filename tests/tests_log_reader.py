from collector.log_reader import read_logs


for log in read_logs("collector/sample.log"):
    print(log)