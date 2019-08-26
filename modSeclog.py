# coding:utf-8

import re
import urllib3
import json

Cookie = ""
Host = ""
Referer = ""
Attip = ""
Method = ""
URL = ""
Matched = ""
post_Data = ""
last_Attackip = ""
User_Agent = ""
X_Real_IP = ""
X_Forwarded_For = ""
ruleFile = ""

count = 0



with open('modsec_audit.log','r',encoding="utf-8") as fs:
    for line in fs:
        tempStatus = re.findall('^---[a-zA-Z0-9]{8}---[A-Z]--$',line)
        if len(tempStatus):
            status = tempStatus[0][14:15]
        if status == 'A':
            # 获取攻击IP地址
            Attip = re.findall('(\\d+\\.\\d+\\.\\d+\\.\\d+)',fs.readline())[1]
            Attip = Attip.strip()
            #print(Attip)
        if status == 'B':
            try:
                # 获取url和提交方法
                url_method = fs.readline().split(' ')
                URL = url_method[1].strip()
                #print(URL)
                Method = url_method[0].strip()
                #print(Method)
            except Exception as e:
                print("[B] Error : ", e)
            for b_line in fs:
                tempStatus = re.findall('^---[a-zA-Z0-9]{8}---[A-Z]--$', b_line)
                if len(tempStatus):
                    # 需要将status赋值为获取到新的值，不然status永远都是：B
                    status = tempStatus[0][14:15]
                    break
                # 获取cookie
                cookie_status = b_line.find('Cookie')
                if not cookie_status:
                    Cookie = b_line[8:].strip()
                    #print(Cookie.strip())
                # 获取Referer
                referer_status = b_line.find('Referer')
                if not referer_status:
                    Referer = b_line[9:].strip()
                    #print(Referer.strip())
                # 获取Host
                host_status = b_line.find('Host:')
                if not host_status:
                    Host = b_line[5:].strip()
                    #print(Host.strip())
                # 获取User-Agent
                agent_status = b_line.find('user-agent:')
                if not agent_status:
                    User_Agent = b_line[12:].strip()
                    #print(User_Agent.strip())
                # 获取X-Real-IP
                real_status = b_line.find('X-Real-IP:')
                if not real_status:
                    X_Real_IP = b_line[11:].strip()
                    #print(X_Real_IP.strip())
                # 获取X-Forwarded-For
                forwarded_status = b_line.find('X-Forwarded-For:')
                if not forwarded_status:
                    X_Forwarded_For = b_line[16:].strip()
                    #print(X_Forwarded_For.strip())
        if status == 'C':
            if Method == 'POST':
                for c_line in fs:
                    tempStatus = re.findall('^---[a-zA-Z0-9]{8}---[A-Z]--$', c_line)
                    if len(tempStatus):
                        # 需要将status赋值为获取到新的值，不然status永远都是：C
                        status = tempStatus[0][14:15]
                        break  # 这个break没有跳出内层循环？？？
                    if c_line.strip() != "":
                        post_Data += c_line   # 数据量太大，导致数据库插入失败
        if status == 'H':
            lineCount = 0
            ruleFile = ""
            for h_line in fs:
                lineCount += 1
                tempStatus = re.findall('^---[a-zA-Z0-9]{8}---[A-Z]--$', h_line)
                try:
                    if len(tempStatus):
                        status = tempStatus[0][14:15]
                        break
                except Exception as e:
                    print("[H] Error : ",e)
                    break
                #Matched += h_line.strip()
                MatchedList = re.findall("ModSecurity: Warning\. (.*) \[file",h_line)
                ruleFileList = re.findall(".*\[file \"(.*)\.conf\"]", h_line)
                print("Matched : ", MatchedList)
                print("[rule] : " ,ruleFileList)
                if MatchedList:
                    print("Matched : " ,MatchedList[0])
                    Matched += "[" + str(lineCount) + "]" + MatchedList[0]  # 多行数据，使用数字标识
                if ruleFileList:
                    ruleFile = str(ruleFileList[0]).split('/')[-1] + ".conf"
                    print("[rulefile] : ",ruleFile)

        if status == 'Z':
            # 每次终结的点
            # 写入到elasticSearch中
            log_data = {
                "Host":Host,
                "Method":Method,
                "URL":URL,
                "Referer":Referer,
                "Attip":Attip,
                "POST-Data":post_Data,
                "Cookie":Cookie,
                "Matched":Matched,
                "User-Agent":User_Agent,
                "X_Real_IP":X_Real_IP,
                "X_Forwarded_For":X_Forwarded_For,
                "ruleFile":ruleFile
            }
            headers = {
                "Content-Type":"application/json",   # 一定要有这头部
                "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0"
            }
            # write
            count += 1
            elastic_url = 'http://127.0.0.1:9200/log4/modsec/' + str(count)
            write_elastic = urllib3.PoolManager()
            req = write_elastic.request(method='PUT',
                                        url=elastic_url,
                                        body=json.dumps(log_data),
                                        headers=headers)
            Matched = ""
