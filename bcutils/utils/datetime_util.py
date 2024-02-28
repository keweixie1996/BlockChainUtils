#coding=utf-8


import time
import datetime
import pytz
import math
import re


def get_sep_date(today):
    if isinstance(today, str):
        dt = str2datetime(today)
    elif isinstance(today, datetime.datetime):
        dt = today
    else:
        return
    return str(dt.year), str(dt.month).zfill(2), str(dt.day).zfill(2)


def get_current_sep_date():
    dt = datetime.datetime.now()
    #dt = datetime.datetime.utcnow()
    return str(dt.year), str(dt.month).zfill(2), str(dt.day).zfill(2)


def get_current_date(fm="%Y%m%d"):
    return datetime2str(datetime.datetime.now(), fm)


def get_current_timestamp(ms=False):
    if ms:
        return float(round(time.time() * 1000))
    else:
        return round(time.time())

 
def strformat(today, fm_new, fm_old="%Y%m%d"):
     return time.strftime(fm_new, time.strptime(today, fm_old))


def str2datetime(today, fm="%Y%m%d"):
    return datetime.datetime.strptime(today, fm)


def get_weekday(date, fm="%Y%m%d"):
    return datetime.datetime.strptime(date, fm).weekday()


def datetime2str(dt, fm="%Y%m%d"):
    return dt.strftime(fm)


def timestamp2datetime(timestamp, ms=False):
    if isinstance(timestamp, str):
        timestamp = int(timestamp)
    if ms:
        timestamp /= 1000
    return datetime.datetime.utcfromtimestamp(timestamp)
    #return datetime.datetime.fromtimestamp(timestamp)


def datetime2timestamp(dt, ms=False):
    tsp = time.mktime(dt.timetuple())
    if ms:
        tsp *= 1000
    return tsp


def timestamp2str(timestamp, ms=False, fm="%Y%m%d"):
    dt = timestamp2datetime(timestamp, ms)
    return datetime2str(dt,fm)


def utc_timestamp2str(timestamp, ms=False, fm="%Y%m%d"):
    dt = timestamp2datetime(timestamp, ms)
    dt = dt.astimezone(pytz.utc)
    return datetime2str(dt,fm)


def str2timestamp(today, ms=False, fm="%Y%m%d"):
    return datetime2timestamp(str2datetime(today, fm), ms)


def get_hour_ago(today, start_hour, duration=1, fm="%H"):
    dt_start = str2datetime(today + start_hour, "%Y%m%d" + fm)
    dt_cur = dt_start - datetime.timedelta(hours=duration)
    ymd_cur, h_cur = datetime2str(dt_cur, "%Y%m%d"), str(dt_cur.hour).zfill(2)
    return ymd_cur, h_cur


def get_hour_list_ago(today, start_hour, duration=1, fm="%H"):
    hour_list = []
    dt_start = str2datetime(today + start_hour, "%Y%m%d" + fm)
    for i in range(0, duration):
        dt_cur = dt_start - datetime.timedelta(hours = i)
        ymd_cur, h_cur = datetime2str(dt_cur, "%Y%m%d"), str(dt_cur.hour).zfill(2)
        hour_list.append((ymd_cur, h_cur))
    return hour_list


def get_hour_list(start_ymdh, end_ymdh, fm="%Y%m%d%H"):
    dt_start = str2datetime(start_ymdh, fm)
    dt_end = str2datetime(end_ymdh, fm)
    hour_list = [(start_ymdh[:8], start_ymdh[8:])]
    while dt_start != dt_end:
        dt_start += datetime.timedelta(hours = 1)
        ymdh = datetime2str(dt_start, fm)
        hour_list.append((ymdh[:8], ymdh[8:]))
    return hour_list


def get_date_ago(start_date, duration=1, fm="%Y%m%d"):
    dt_start = str2datetime(start_date, fm)
    dt_cur = dt_start - datetime.timedelta(days = duration)
    return datetime2str(dt_cur,fm)
 

def get_date_list_ago(start_date, duration=1, fm="%Y%m%d"):
    date_list = []
    dt_start = str2datetime(start_date, fm)
    for i in range(0, duration):
        dt_cur = dt_start - datetime.timedelta(days = i)
        date_list.append(datetime2str(dt_cur,fm))
    return date_list
 

def get_date_list(start_date, end_date, fm="%Y%m%d"):
    dt_start = str2datetime(start_date, fm)
    dt_end = str2datetime(end_date, fm)
    date_list = [datetime2str(dt_start,fm)]
    while dt_start != dt_end:
        dt_start += datetime.timedelta(days = 1)
        date_list.append(datetime2str(dt_start,fm))
    return date_list


def get_delta_days(start_date, end_date, fm="%Y%m%d"):
    return (str2datetime(end_date, fm) - str2datetime(start_date, fm)).days


def get_delta_months(start_date, end_date, fm="%Y%m%d"):
    start_year = str2datetime(start_date, fm).year
    start_mon = str2datetime(start_date, fm).month
    end_year = str2datetime(end_date, fm).year
    end_mon = str2datetime(end_date, fm).month
    return (end_year - start_year) * 12 + (end_mon - start_mon)


def get_delta_years(start_date, end_date, fm="%Y%m%d"):
    start_year = str2datetime(start_date, fm).year
    end_year = str2datetime(end_date, fm).year
    # return get_delta_months(start_date, end_date, fm) / 12
    return end_year - start_year


def get_time_seg(client_time, parts=12): 
    if 24 % parts != 0:
        print('error parts!') 
    else:
        try:
            dt = dt_parser.parse(client_time)
        except ValueError:
            return
        return int(math.floor(dt.hour / int(24 / parts)))

def year2days(year):
    return int(year * 365 + year / 4)


if __name__ == '__main__':
    # print(timestamp2str("1583798400000", ms=True))
    # print(str2timestamp("18990101"))
    # print(get_sep_date("20190814"))
    # print(get_current_sep_date())
    # print(get_current_timestamp(ms=True))
    #client_time = "2020-05-05T23:22:36.009+0530"
    s = int(time.time())
    r = timestamp2str(s, fm="%Y-%m-%dT%H:%M:%S")
    print(s,r,str2timestamp(r, fm="%Y-%m-%dT%H:%M:%S"))
    exit(0)
    client_time = "2022-10-10T11:04:00.000+0530"
    #client_time = "2022-09-30T16:50:00.000+0530"
    print(client2timestamp(client_time))
    d = "2022-09-30T16:50:00"
    print(str2timestamp(d, fm="%Y-%m-%dT%H:%M:%S"))
    exit(0)
    #print(client2datetime(client_time))
    #print(client2timestamp(client_time, ms=True))
    print(get_hour_ago("20200720", "00", 1))
    print(get_hour_list_ago("20200720", "02", 7))
    print(get_hour_list("2021030800", "2021030812"))
    # print(get_date_ago("20190814", duration=3))
    # print(get_date_list_ago("20190814", duration=3))
    # print(get_date_list("20190810", "20190814"))
    # print(get_delta_days("20190614", "20190814"))
    # print(get_delta_months("20181231", "20190213"))
    # print(get_delta_years("20181231", "20190814"))
    # print(get_delta_years("20181231", "20190101"))
    # print(get_time_seg("2019-08-14T02:19:33.171+0530", parts=12))
    # print(client2timestamp_v2("2019-08-14T02:19:33.171+0530"))
    print(timestamp2str(1640765945, fm="%Y-%m-%d %H:%M:%S"))
    print(timestamp2str(1640765945+5.5*3600, fm="%Y-%m-%d %H:%M:%S"))


