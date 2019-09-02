# coding:utf-8

import re
import urllib3
import json
from elasticsearch import Elasticsearch

time = ""
domain = ""
method = ""
uri = ""
token = ""
device = ""
attip_1 = ""
attip_2 = ""
appName = ""
attcktype = ""
attckdetail = ""
attack_msg = ""
warning_id = ""
warning_msg = ""


count = 0


es = Elasticsearch(
    ['127.0.0.1:9200'],
)



with open('modsec_audit.log','r',encoding="utf-8") as fs:
    for line in fs:
        tempStatus = re.findall('^---[a-zA-Z0-9]{8}---[A-Z]--$',line)
        if len(tempStatus):
            status = tempStatus[0][14:15]
        if status == 'A':
            contentA = fs.readline()
            # 获取攻击时间
            time = re.findall('\[(.*)\]',contentA)[0].split(' ')[0]
            #print(AttTime)
            # 获取攻击IP地址
            Attip = re.findall('(\\d+\\.\\d+\\.\\d+\\.\\d+)',contentA)[1]
            Attip = Attip.strip()
            #print(Attip)
        if status == 'B':
            try:
                # 获取url和提交方法
                url_method = fs.readline().split(' ')
                uri = url_method[1].strip()
                #print(URL)
                method = url_method[0].strip()
                #print(Method)
            except Exception as e:
                print("[B] Error : ", e)
            for b_line in fs:
                tempStatus = re.findall('^---[a-zA-Z0-9]{8}---[A-Z]--$', b_line)
                if len(tempStatus):
                    # 需要将status赋值为获取到新的值，不然status永远都是：B
                    status = tempStatus[0][14:15]
                    break   # 这个break没有跳出内层循环？？？
                # 获取token
                token_status = b_line.find('access-token')
                if not token_status:
                    token = b_line[13:].strip()
                    #print(token.strip())
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
                # 获取Host(domain)
                host_status = b_line.find('Host:')
                if not host_status:
                    domain = b_line[5:].strip()
                    #print(Host.strip())
                # 获取User-Agent
                agent_status = b_line.find('user-agent:')
                if not agent_status:
                    User_Agent = b_line[12:].strip()
                    #print(User_Agent.strip())
                # 获取X-Real-IP
                real_status = b_line.find('X-Real-IP:')
                if not real_status:
                    attip_2 = b_line[11:].strip()
                    #print(X_Real_IP.strip())
                # 获取X-Forwarded-For
                forwarded_status = b_line.find('X-Forwarded-For:')
                if not forwarded_status:
                    attip_1 = b_line[16:].strip()
                    #print(X_Forwarded_For.strip())
                # 获取device
                device_status = b_line.find('device')
                if not device_status:
                    device = b_line[7:].strip()
                    #print(device.strip())
        if status == 'C':
            if method == 'POST':
                for c_line in fs:
                    tempStatus = re.findall('^---[a-zA-Z0-9]{8}---[A-Z]--$', c_line)
                    if len(tempStatus):
                        # 需要将status赋值为获取到新的值，不然status永远都是：C
                        status = tempStatus[0][14:15]
                        break  # 这个break没有跳出内层循环？？？
                    # if c_line.strip() != "":
                    #     post_Data += c_line   # 数据量太大，导致数据库插入失败
                    try:
                        # 但是可能存在不是json格式的数据包，此时无法进行做处理
                        # 也有可能不存在该appName字段，此时也无法处理
                        appName = json.loads(c_line)['appName']
                        #print(appName)
                    except Exception as e:
                        print('[+] POST data Error : ' ,e)
                        pass
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
                # 获取攻击类型
                attcktype_re = re.findall('\[tag \"(attack.*?)\"\]', h_line)
                # 并不是全部都是攻击，获取攻击详情
                attckdetail_re = re.findall('\[tag \"OWASP_CRS(.*?)\"\]',h_line)
                attack_msg_re = re.findall('\[msg \"(.*?)\"\]',h_line)
                warning_id_re = re.findall('\[file \"(.*?)\"\]',h_line)
                warning_msg_re = re.findall('ModSecurity: Warning. (.*)\[file',h_line)

                if attcktype_re:
                    attcktype += "[" + str(lineCount) + "]" + attcktype_re[0] + ";"  # 多行数据，使用数字标识
                # 有攻击类型并不是所有都有对应的攻击详情
                if attckdetail_re:
                    attckdetail += "[" + str(lineCount) + "]" + attckdetail_re[0].split('/')[2] + ";"  # 多行数据，使用数字标识
                if attack_msg_re:
                    attack_msg += "[" + str(lineCount) + "]" + attack_msg_re[0] + ";"  # 多行数据，使用数字标识
                if warning_id_re:
                    warning_id += "[" + str(lineCount) + "]" + warning_id_re[0].split('/')[-1] + ";"  # 多行数据，使用数字标识
                    #print(warning_id)
                if warning_msg_re:
                    warning_msg += "[" + str(lineCount) + "]" + warning_msg_re[0] + ";"  # 多行数据，使用数字标识
                    print(warning_msg)
                # if ruleFileList:
                #     ruleFile = str(ruleFileList[0]).split('/')[-1] + ".conf"

        if status == 'Z':
            # 每次终结的点
            # 写入到elasticSearch中
            log_data = {
                "time":time,
                "domain":domain,
                "method":method,
                "uri":uri,
                "token":token,
                "device":device,
                "attip_1":attip_1,
                "attip_2":attip_2,
                "appName":appName,
                "attcktype":attcktype,
                "attckdetail":attckdetail,
                "attack_msg":attack_msg,
                "warning_id":warning_id,
                "warning_msg":warning_msg
            }
            headers = {
                "Content-Type":"application/json",   # 一定要有这头部
                "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:60.0) Gecko/20100101 Firefox/60.0"
            }
            # 以主域名作为索引
            index = ""
            j = 0
            domain_re = domain.split('.')
            count += 1
            es.index(index=domain_re[1],doc_type=domain_re[0],id=count,body=json.dumps(log_data))
            attcktype = ""
            attckdetail = ""
            attack_msg = ""
            warning_id = ""
            warning_msg = ""
            # 因为Z块中只有空行，所以当再次循环时，会导致重新进入到Z中，并将原来的数据重新写入，直到空行被完全读完
            status = ""
            print("Write done : " + str(count))
