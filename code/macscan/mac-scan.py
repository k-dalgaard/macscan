from datetime import datetime
import requests
import json
#from requests.auth import HTTPBasicAuth
requests.packages.urllib3.disable_warnings()
from pprint import pprint
import logging
import sys
import time
import re
#from sit_ssh import Wrapper
sys.path.append('/code/basecode/')
from ios import Wrapper
import config
#import base64
import getpass
import sqlite3
from sqlite3 import Error
import csv
import getopt
import pandas as pd

#import base64
#import hashlib

url = 'http://macvendors.co/api/%s'

'''
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    #filemode='w',
    handlers=[
        logging.FileHandler("frh-script.log"),
        #logging.StreamHandler()
    ]
)
'''

logger=logging.getLogger()
logger.info("#############################")
logger.info("  Python Script started      ")
logger.info("#############################")


#sw_authority = input('Indtast switch ip: ')
#sw_username = input('username: ')
#password = getpass.getpass('password: ')

#passw  = base64.b64decode(b'T0JvRk8yS21VZmtyQzhsZEx1SUE=')

sw_username = config.username
password =  config.passwd




#sw_authority =  '10.100.22.5'

####################################################################
#/home/API-CPI-NBI/.local/lib/python3.6/site-packages/ntc_templates/templates/cisco_ios_show_authentication_sessions_details.textfsm
#####################################################################

sql_create_intf_table = ''' CREATE TABLE IF NOT EXISTS intf(
                                    interface text NOT NULL
                                    )'''

sql_create_vendor_table = ''' CREATE TABLE IF NOT EXISTS macvendor(
                                        mac text NOT NULL,
                                        vendor test NOT NULL
                                    )'''

sql_create_datalist_table = ''' CREATE TABLE IF NOT EXISTS datalist(
                                        location text NOT NULL,
                                        sw_ip text NOT NULL,
                                        sw_hostname text NOT NULL,
                                        sw_type text NOT NULL,
                                        intf text NOT NULL,
                                        mac text NOT NULL,
                                        vlan text NOT NULL,
                                        ipv4 text NOT NULL,
                                        device_type text NOT NULL,
                                        username text NOT NULL,
                                        auth_domain text NOT NULL,
                                        auth_status text NOT NULL,
                                        dot1x_status text NOT NULL,
                                        mab_status text NOT NULL,
                                        vendor text NOT NULL,
                                        date text NOT NULL
                                    )'''


mac_list = []
sw_lst=[]
connect_status = ''


def network_login():
    #sw_authority = "10.100.20.5"
    #print('inden switchlogin#1')
    sw = Wrapper(authority=sw_authority, username=sw_username, password=password, protocol='ssh')
    #print('inden switchlogin#2')
    loggedin = sw.login()
    return sw,loggedin

def network_logout(sw):
    sw.logout()


def show_mac_address_table(sw):
        #logger.info("Get show authentications sesssion interface from switch")
        cmd = "show mac address-table"
        result = sw.show_mac_address_table(cmd)
        #exit()
        return(result)

def convert_mac(mac_address):
    if str(mac_address).count(".",0,len(mac_address))==2 and len(mac_address)==14:
        #Convert MAC from xxxx.xxxx.xxxx format to xx:xx:xx:xx:xx:xx format
        mac_address=str(mac_address)
        mac_address=mac_address.replace(".","")
        count = 1
        mac_address=list(mac_address)
        while(count<14):
            mac_address.insert(count+1,":")
            count+=3
    return (''.join(mac_address)).lower()
    



def mac_vendor_lookup(mac_address,conn):
         result_final = ''
         mac = convert_mac(mac_address)
         rows = select_mac(conn,mac)
         logger.info("MAC_VENDOR_LOOKUP")
         #print("#############################")
         if str(rows) == '[]':
            logger.info("Checker " + mac + " mod http API")
            #print("checker", mac, " mod http api")
            #r = requests.get(url % mac[0:-9])
            vendor = requests.get('http://api.macvendors.com/' + mac[0:-9])
            #print("status_code: ", vendor.status_code)
            logger.info("API call status_code:   " + str(vendor.status_code))
            time.sleep(1)
            #print(r.json())
            
            #pprint(r_dict)
            #pprint(r_dict['result'])
            if vendor.status_code == 200:
                result_final = vendor.text
            elif vendor.status_code == 404:
                #pprint(vendor)
                r_dict = vendor.json()
                #pprint(r_dict)
                for key, value in  r_dict['errors'].items():
                    k = key
            #       print(k)
                    v = value
                    if value  == 'Not Found':
                        logger.info(mac + ' not found in http API call')
                        #print("Mac ", mac, ' not found in API call')
                        result_final = 'Not Found'
            else:
                result_final = 'server_error'
                logger.info("API call response with server_error")

            if result_final == 'Not Found':
               insert_db_values(conn, mac[0:-9], result_final)
               #print(mac[0:-9]+ '' + result_final)
               return result_final
            elif result_final == 'server_error':
                insert_db_values(conn, mac[0:-9], result_final)
                #print(mac[0:-9]+ '' + result_final)
                return result_final
            else:
               #insert_db_values(conn, mac[0:-9], r_dict['result']['company'])
               insert_db_values(conn, mac[0:-9], result_final)
               #print('database created: ' + r_dict['result']['company'] )
               #print('database created: ' + result_final )
               logger.info("database entry create: " +  result_final)
              # print(r_dict['result']['mac_prefix'] + ' ' + r_dict['result']['company'])
               #return r_dict['result']['company']
               return result_final
         else:
            for r in rows:
               company = str(r)
            #print(mac, ' exist in db: ' + company[2:-3])
            logger.info('exist in db: ' + company[2:-3])
            return company[2:-3]





def select_mac(conn,mac):
    cur = conn.cursor()
    sql = 'SELECT vendor FROM macvendor where mac = \"' + mac[0:-9] + '\"'
    #print(sql)
    cur.execute(sql)
    rows = cur.fetchall()
    return rows




def get_sw_auth_session_detail(sw,intf):
        #/home/API-CPI-NBI/.local/lib/python3.6/site-packages/ntc_templates/templates/cisco_ios_show_authentication_sessions_details.textfsm
        #logger.info("Get show authentications sesssion interface from switch")
        cmd = 'show authentication sessions interface ' + intf + ' detail'
        result = sw.show_auth_session_detail(cmd)
        return(result)


def create_mac_list(data,sw):             
        for key in data:
            #pprint(key)
            if key['destination_port'] !=  'CPU' and key['type'] == 'STATIC':
                auth_detail = get_sw_auth_session_detail(sw,key['destination_port'])
                for d in auth_detail:
                    auth_device = d['device_type']
                    auth_user   = d['username'] 

                mac  = {
                       'Lokation'   :    lokation(sw_authority),
                       'sw_ip'      :    sw_authority,
                       
                       'intf'       :    key['destination_port'],
                       'mac'        :    key['destination_address'],
                       'vlan'       :    key['vlan'],
                       'type'       :    key['type'],
                       'device_type':    auth_device,
                       'username'   :    auth_user,
                       'vendor'     :    mac_vendor_lookup(key['destination_address'])
#                       'vendor'     :    mac_vendor_lookup('02:CD:10:11:00:0D')
                       }
                mac_list.append(mac)
#        pprint(mac_list) 



def create_connection(db):
    """ create a database connection to a database that resides
        in the memory
    """
    conn = None;
    try:
        conn = sqlite3.connect(db, detect_types=sqlite3.PARSE_COLNAMES)  #only in mory
        logger.info(db + " Sqlite3 version:  " + sqlite3.version)
#        print(sqlite3.version)
    except Error as e:
        print(e)
 #   finally:
 #       if conn:
 #           conn.close()
    return conn


def create_table(conn, create_table_sql):
    """ create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    #print(create_table_sql,conn)
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)

def insert_db_interface(conn, db_input):
    #print(conn)
    #print(db_input)
#    sql = ''' INSERT INTO interface Values('test'); '''
    sql = ''' INSERT INTO intf(interface)
              VALUES(?) '''
    cur = conn.cursor()
    #print(sql,db_input)
    cur.execute(sql,(db_input,))
    conn.commit()
    return cur.lastrowid


def insert_db_values(conn, mac, vendor):
     cur = conn.cursor()
     sql = ''' INSERT INTO  macvendor(mac,vendor)
              VALUES(?,?) '''
     #cur = conn.cursor()
     cur.execute(sql,[mac,vendor])
     conn.commit()
     cur.close()
     return cur.lastrowid



def remove_duplicataes_db(conn):
    """
    Remove all duplicates in database

    """
    sql = 'delete from intf where rowid NOT in (select min(rowid) from intf group by interface)'
    cur = conn.cursor()
    cur.execute(sql)

def select_all_intf(conn):
    """
    Query all rows in the tasks table
    :param conn: the Connection object
    :return:
    """
    cur = conn.cursor()
    cur.execute("SELECT * FROM intf")

    rows = cur.fetchall()
    #print('rows: ', rows)
    return  rows
#    for row in rows:
#        print(str(row)[2:-3])

def select_intf(conn,intf):
    cur = conn.cursor()
    sql = 'SELECT interface FROM intf where interface = \"' + intf + '\"'
#    print(sql)
    cur.execute(sql)
    rows = cur.fetchall()
#    print(str(rows)[2:-3])
    #for row in rows:
     #   print(str(row)[2:-3])



def get_intf(conn,result):
    for key in result:
        #pprint(result)
        
        
        if 'CPU' not in key['destination_port'] and key['type'] == 'STATIC':
            #print(key)
            #print(key['destination_port'])
            #if 'Vl' not in key['destination_port']:
            if any('Vl' not in port for port in key['destination_port']):
                #print('match')
                #print(key['destination_port'])
               
                #var =  key['destination_port'].replace('Gi','GigabitEthernet') 
                modified_list = [s.replace('Gi', 'GigabitEthernet') for s in key['destination_port']]
                #print(modified_list)
                s = modified_list[0]
                #print(type(s))

                
                insert_db_interface(conn, s)  
    



def create_data_list(data,sw,db_intf_conn,db_vendor_conn,swlst,sw_hostname,hardware,data_conn):
       sw_loc = ''
       mac_vlan=''
       db_data = select_all_intf(db_intf_conn)
       #print('*************SW-LIST: ', swlst)
       dateTimeObj = datetime.now()
       timestampStr = dateTimeObj.strftime("%d-%b-%Y %H:%M:%S")
       #sw_hostname = sw.exec_command('sh run | i hostname')[9:]
       for key in db_data:
                auth_detail = get_sw_auth_session_detail(sw,str(key)[2:-3])
                #pprint(auth_detail)                   
                for info in auth_detail:
                 #   pprint(info)
                    for m in data:
                        #print(m['vlan'])
                        if 'CPU' not in m['destination_port']  and m['type'] == 'STATIC':
                           #var  =  m['destination_port'].replace('Gi','GigabitEthernet') 
                           modified_list = [s.replace('Gi', 'GigabitEthernet') for s in m['destination_port']]
                           var = modified_list[0]
                           #print('----------------------------')
                           #print('var: ', var)
                           #print('info: ', info['interface'])
                           #print('m_dest_add: ', m['destination_address'])
                           #print('info_mac: ', info['mac'])
                           
                           if (var == info['interface'] and m['destination_address'] == info['mac']):
                                #print('----------------------------')
                                #print('var: ', var)
                                #print('info: ', info['interface'])
                                #print('m_dest_add: ', m['destination_address'])
                                #print('info_mac: ', info['mac'])
                                #print('m_vlan: ', m['vlan'])
                                mac_vlan = m['vlan']
                                db_result = select_loc_db_datalist(data_conn,m['destination_address'])
                                if db_result != '':
                                    for loc in db_result:
                                        #print(type(loc))
                                        #print('bd_result= ', db_result[0])
                                        #print('db_result= ', db_result[2:3])
                                        #print('db_result= ', str(db_result[0]))
                                        #print('db_result= ', str(db_result[0])[2:2])
                                        #print('db_result= ', str(db_result[0])[2:-3])
                                        logger.info('location exist in db: ' + str(db_result[0])[2:-3])

                                        sw_loc = str(db_result[0])[2:-3]
                                else:
                                    sw_loc = ''
                    if swlst != []:           
                        for rows in swlst:
                            if rows[0] == sw_authority:
                                sw_lokation = rows[1]
                    else:
                        if sw_loc == '':
                            sw_lokation = 'not defined'
                        else:
                            sw_lokation = sw_loc
                    mac  = {
                       'Lokation'   :    sw_lokation,
                       'sw_ip'      :    sw_authority,
                       'sw_hostname':    sw_hostname,
                       'sw_type'    :    hardware,
                       'intf'       :    info['interface'],
                       'mac'        :    info['mac'],
                       'vlan'       :    mac_vlan,
                       'ipv4'       :    info['ipv4_address'],
                       'device_type':    info['device_type'],
                       'username'   :    info['username'],
                       'auth_domain':    info['domain'],
                       'auth_status':    info['status'],
                       'dot1x_status':    info['dot1x'],
                       'mab_status' :    info['mab'], 
                       'vendor'     :    mac_vendor_lookup(info['mac'],db_vendor_conn),
                       'date'       :    timestampStr
#                       'vendor'     :    mac_vendor_lookup('02:CD:10:11:00:0D')
                       }
                    #print(mac)
                    mac_list.append(mac)

def select_mac_db_datalist(conn,mac):
    cur = conn.cursor()
    sql = 'SELECT mac FROM datalist where mac = \"' + mac + '\"'
    cur.execute(sql)
    rows = cur.fetchall()
    #print('db_mac: ', rows)
    return rows

def select_loc_db_datalist(conn,mac):
    cur = conn.cursor()
    sql = 'SELECT location FROM datalist where mac = \"' + mac + '\"'
    cur.execute(sql)
    rows = cur.fetchall()
    #print('db_mac: ', rows)
    return rows


def insert_db_mac_values(conn):
    for unit in mac_list:
        result = select_mac_db_datalist(conn,unit['mac'])
        if result == []:
            cur = conn.cursor()
            sql = ''' INSERT INTO  datalist(location,sw_ip,sw_hostname,sw_type,intf,mac,vlan,ipv4,device_type,username,auth_domain,auth_status,dot1x_status,mab_status,vendor,date)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) '''
            cur = conn.cursor()
            cur.execute(sql,(unit['Lokation'],
                        unit['sw_ip'],
                        unit['sw_hostname'],
                        unit['sw_type'],
                        unit['intf'],
                        unit['mac'],
                        unit['vlan'],
                        unit['ipv4'],
                        unit['device_type'],
                        unit['username'],
                        unit['auth_domain'],
                        unit['auth_status'],
                        unit['dot1x_status'],
                        unit['mab_status'],
                        unit['vendor'],
                        unit['date'])
                    )
            conn.commit()
        else:
            cur = conn.cursor()
            sql = ''' update datalist set location = ?, 
                                        sw_ip = ?,
                                        sw_hostname = ?,
                                        sw_type = ?, 
                                        intf = ?, 
                                        vlan = ?, 
                                        ipv4 = ?, 
                                        device_type = ?, 
                                        username = ?, 
                                        auth_domain = ?, 
                                        auth_status = ?, 
                                        dot1x_status = ?, 
                                        mab_status = ?, 
                                        date = ? 
                                        where mac = ?'''

            records_to_update= (unit['Lokation'],
                                unit['sw_ip'],
                                unit['sw_hostname'],
                                unit['sw_type'],
                                unit['intf'],
                                unit['vlan'],
                                unit['ipv4'],
                                unit['device_type'],
                                unit['username'],
                                unit['auth_domain'],
                                unit['auth_status'],
                                unit['dot1x_status'],
                                unit['mab_status'],
                                unit['date'],
                                unit['mac']
                            )
            cur = conn.cursor()
            cur.execute(sql,records_to_update)
            conn.commit()
    #return cur.lastrowid            


def export_db_to_csv(data_conn):
    db_df = pd.read_sql_query("SELECT * FROM datalist order by location", data_conn)
    db_df.to_csv('database.csv', index=False)




##Script starts here
if __name__ == "__main__":
        with open('failed_hosts.txt','w') as f:
            f.close()
        dateTimeObj = datetime.now()
        timestampStr = dateTimeObj.strftime("%d-%b-%Y %H:%M:%S")
        logger.info('Script started at: ' + timestampStr)
        argv = sys.argv[1:] 
        no_file = ''
        lst=[]
        try: 
           options, args = getopt.getopt(sys.argv[1:], 'f', ['file='])
           if argv != []:
              for opt, arg in options:
                  if opt in ('-f', '--file'):
                    filename = argv[1]
                    with open(filename) as file: 
                            reader = csv.reader(file) 
                            for row in reader:
                                sw_lst.append(row)
                                #pprint(sw_lst)
                    for ip,location in sw_lst:
                        lst.append(ip)
                        #print(lst)
                            
                     #pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
              #       lst=[]
        
           else:
              sw_authority = input('Indtast switch ip: ')              
              lst +=  [sw_authority]
              no_file = 'no_file'
        except getopt.GetoptError:
              print('The wrong option is provided')
              sys.exit(2)


#        with open('devices.text') as f: 
#             fstring = f.readlines() 
#        pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
#        lst=[]
        
#        for line in fstring:
#            lst.append(pattern.search(line)[0])



       # db = ':memory:'
       # intf_conn = create_connection(db) ##db connect memory dabase for interfaces 
       # create_table(intf_conn, sql_create_intf_table) ##greate table in database
        #sw_username = input('username: ')
        #password = getpass.getpass('password: ')

        #sw_username = 'keda'
        #password = ''

        db_mac =  '/code/basecode/macvendor.db'
        vendor_conn = create_connection(db_mac) ##db connect memory dabase for  macvendor 
        create_table(vendor_conn, sql_create_vendor_table) ##greate table in database

        db_data = '/code/macscan/datalist.db'
        data_conn =  create_connection(db_data) ##db connect dabase for datalist.db
        create_table(data_conn, sql_create_datalist_table) ##greate table in database

        #db = ':memory:'
        #intf_conn = create_connection(db) ##db connect memory dabase for interfaces 
        #create_table(intf_conn, sql_create_intf_table) ##greate table in database
        #intf_conn.close()
        #print('***********SW list: ', sw_lst)
        
        for ip in range(len(lst)):
           db = ':memory:'
           #db = 'intf.db'
           intf_conn = create_connection(db) ##db connect memory dabase for interfaces 
           create_table(intf_conn, sql_create_intf_table) ##greate table in database
           
           sw_authority = lst[ip]
           #print('for network login')
           sw_var = network_login()   ##login to switch
           sw = sw_var[0]
           loggedin = sw_var[1]
           #pprint(sw)
           if loggedin == True:
                result = show_mac_address_table(sw)  ##get show mac address-table from switch
                get_intf(intf_conn,result) ##store interface from mac result in database
                remove_duplicataes_db(intf_conn) #remove dublicate interfaces in dabase
                rows_intf = select_all_intf(intf_conn)
                print(rows_intf)
                if rows_intf != []:
                        #print(type(lst_intf))
                        #print(lst_intf)
        #               sw_hostname = sw.exec_command('sh run | i hostname')[9:]
                        #get hostname and hardware model
                        sh_ver_result = sw.show_version()
                        for v in sh_ver_result:
                            sw_hostname =   v['hostname']
                            hardware    =   v['hardware']
                        create_data_list(result,sw,intf_conn,vendor_conn,sw_lst,sw_hostname,hardware[0],data_conn)
                        intf_conn.close()
                        #vendor_conn.close()

                        #keys = mac_list[0].keys()
                        #print(keys)
                        #print(type(mac_list))
        #               print(mac_list)
                        network_logout(sw)
           elif loggedin == False:
                #print('connections to host: ',sw_authority, ' failed' )
                #logger.info('connections to host: ',sw_authority, ' failed')
                with open('failed_hosts.txt','a') as f:
                    f.write('connections to host: ' + sw_authority + ' failed\n')
                    f.close()
                    #print('connections to host: ',sw_authority, ' failed\n', file=f )


        
        if no_file == 'no_file' and loggedin == True:
            if mac_list !=[]:
                with open('krfo_mac_lst.csv','w') as csv_file:
                    f = csv.DictWriter(csv_file, fieldnames=mac_list[0].keys(),)
                    f.writeheader()
                    f.writerows(mac_list)
            pprint(mac_list)
        
        #print(mac_list)
        if mac_list != []:
            insert_db_mac_values(data_conn)
            export_db_to_csv(data_conn)
       # for key in mac_list:
        #         print('LOK:' + key['Lokation'] + '\tswitch:' + key['sw_ip'] + ' interface: ' + key['intf'] + '\tMac: ' + key['mac'] + ' IP: ' + key['ipv4'] +  ' vlan:' + key['vlan'] + ' device: ' + key['device_type'] + '\tuser:' + key['username'] + '\tVendor:' + key['vendor'])
            vendor_conn.close()
            data_conn.close()
            intf_conn.close()
        dateTimeObj = datetime.now()
        timestampStr = dateTimeObj.strftime("%d-%b-%Y %H:%M:%S")
        logger.info('Script ended at: ' + timestampStr)
        #pprint(mac_list)


