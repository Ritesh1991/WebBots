#!/usr/bin/env python
import sys
import requests
import re
from bs4 import BeautifulSoup
import html5lib

'''==================== USAGE ===================='''
  # 1.    bot  = InterpalsBot() #creates an bot object
  
  # 2.    bot.visitFilteredUsersProfile()  # visits all profiles earlier set up in the fields:
        # '''CONFIG-You SHALL modify ONLY THIS part'''
            # MIN_AGE= 21
            # MAX_AGE= 25
            # SEX= 'F'
            # CONTINENTS= 'NorthAmerica'
            # COUNTRY= ''
            # LOGIN= u"yourmail@gmail.com"  
            # PASSWORD=u"yourpassword"
        # '''-------------CONFIG-End---------------''' 
  
  # 3.    bot.sendMessage("UserWeirdName","Hi!")          #send message "Hi!" to a user UserWeirdName 
  
  # 4.    bot.commentProfilePhoto("UserWeirdName","great photo!")  #send comment message "great photo!" to a profile photo of a user UserWeirdName 
'''================== USAGE-END =================='''

PY2 = sys.version_info[0] == 2
if PY2:
    raise Exception("Please use finally Python3.x version :)")

   
class InterpalsBot():

    '''CONFIG - You SHALL modify ONLY THIS part'''
    MIN_AGE= 26
    MAX_AGE= 30
    SEX= 'F'
    CONTINENTS= 'Europe'
    COUNTRY= ''
    LOGIN= u"yourmail@gmail.com"  
    PASSWORD=u"yourpassword"
    '''-------------CONFIG-End---------------''' 
    
    RequestAttributes={
        "SEX":{"M":"MALE","F":"FEMALE","MF":""},
        "CONTINENT":{"NorthAmerica":"NA", "SouthAmerica":"SA", "Asia":"AS", "Europe":"EU", "Oceania":"OC","Africa":"AF","All":""},
        "COUNTRY":{
        "Afghanistan":"AF",
        "Albania": "AL",
        "Algeria": "DZ",
        "American Samoa": "AS",
        "Andorra": "AD",
        "Angola": "AO",
        "Anguilla": "AI",
        "Antigua and Barbuda": "AG",
        "Argentina": "AR",
        "Armenia": "AM",
        "Aruba": "AW",
        "Australia": "AU",
        "Austria": "AT",
        "Azerbaijan": "AZ",
        "Bahamas": "BS",
        "Bahrain": "BH",
        "Bangladesh": "BD",
        "Barbados": "BB",
        "Belarus": "BY",
        "Belgium": "BE",
        "Belize": "BZ",
        "Benin": "BJ",
        "Bermuda": "BM",
        "Bhutan": "BT",
        "Bolivia": "BO",
        "Bosnia and Herzegovina": "BA",
        "Botswana": "BW",
        "Brazil": "BR",
        "British Virgin Islands": "VG",
        "Brunei": "BN",
        "Bulgaria": "BG",
        "Burkina Faso": "BF",
        "Burundi": "BI",
        "Cambodia": "KH",
        "Cameroon": "CM",
        "Canada": "CA",
        "Cape Verde": "CV",
        "Cayman Islands": "KY",
        "Central African Republic": "CF",
        "Chad": "TD",
        "Chile": "CL",
        "China": "CN",
        "Cocos Islands": "CC",
        "Colombia": "CO",
        "Comoros": "KM",
        "Cook Islands": "CK",
        "Costa Rica": "CR",
        "Croatia": "HR",
        "Cuba": "CU",
        "Cyprus": "CY",
        "Czech Republic": "CZ",
        "Democratic Republic of the Congo": "CD",
        "Denmark": "DK",
        "Djibouti": "DJ",
        "Dominica": "DM",
        "Dominican Republic": "DO",
        "East Timor": "TL",
        "Ecuador": "EC",
        "Egypt": "EG",
        "El Salvador": "SV",
        "Equatorial Guinea": "GQ",
        "Eritrea": "ER",
        "Estonia": "EE",
        "Ethiopia": "ET",
        "Falkland Islands": "FK",
        "Faroe Islands": "FO",
        "Fiji": "FJ",
        "Finland": "FI",
        "France": "FR",
        "French Guiana": "GF",
        "French Polynesia": "PF",
        "French Southern Territories": "TF",
        "Gabon": "GA",
        "Gambia": "GM",
        "Georgia": "GE",
        "Germany": "DE",
        "Ghana": "GH",
        "Gibraltar": "GI",
        "Greece": "GR",
        "Greenland": "GL",
        "Grenada": "GD",
        "Guadeloupe": "GP",
        "Guam": "GU",
        "Guatemala": "GT",
        "Guernsey": "GN",
        "Guinea-Bissau": "GW",
        "Guyana": "GY",
        "Haiti": "HT",
        "Honduras": "HN",
        "Hong Kong": "HK",
        "Hungary": "HU",
        "Iceland": "IS",
        "India": "IN",
        "Indonesia": "ID",
        "Iran": "IR",
        "Iraq": "IQ",
        "Ireland": "IE",
        "Isle of Man": "IM",
        "Israel": "IL",
        "Italy": "IT",
        "Ivory Coast": "CI",
        "Jamaica": "JM",
        "Japan": "JP",
        "Jersey": "JE",
        "Jordan": "JO",
        "Kazakhstan": "KZ",
        "Kenya": "KE",
        "Kiribati": "KI",
        "Kuwait": "KW",
        "Kyrgyzstan": "KG",
        "Laos": "LA",
        "Latvia": "LV",
        "Lebanon": "LB",
        "Lesotho": "LS",
        "Liberia": "LR",
        "Libya": "LY",
        "Liechtenstein": "LI",
        "Lithuania": "LT",
        "Luxembourg": "LU",
        "Macao": "MO",
        "Macedonia": "MK",
        "Madagascar": "MG",
        "Malawi": "MW",
        "Malaysia": "MY",
        "Maldives": "MV",
        "Mali": "ML",
        "Malta": "MT",
        "Marshall Islands": "MH",
        "Martinique": "MQ",
        "Mauritania": "MR",
        "Mauritius": "MU",
        "Mayotte": "YT",
        "Mexico": "MX",
        "Micronesia": "FM",
        "Moldova": "MD",
        "Monaco": "MC",
        "Mongolia": "MN",
        "Montenegro": "ME",
        "Montserrat": "MS",
        "Morocco": "MA",
        "Mozambique": "MZ",
        "Myanmar": "MM",
        "Namibia": "NA",
        "Nepal": "NP",
        "Netherlands": "NL",
        "Netherlands Antilles": "AN",
        "New Caledonia": "NC",
        "New Zealand": "NZ",
        "Nicaragua": "NI",
        "Niger": "NE",
        "Nigeria": "NG",
        "Niue": "NU",
        "North Korea": "KP",
        "Northern Mariana Islands": "MP",
        "Norway": "NO",
        "Oman": "OM",
        "Pakistan": "PK",
        "Palau": "PW",
        "Palestinian Territory": "PS",
        "Panama": "PA",
        "Papua New Guinea": "PG",
        "Paraguay": "PY",
        "Peru": "PE",
        "Philippines": "PH",
        "Poland": "PL",
        "Portugal": "PT",
        "Puerto Rico": "PR",
        "Qatar": "QA",
        "Republic of the Congo": "CG",
        "Reunion": "RE",
        "Romania": "RO",
        "Russia": "RU",
        "Rwanda": "RW",
        "Saint Barthélemy": "BL",
        "Saint Helena": "SH",
        "Saint Kitts and Nevis": "KN",
        "Saint Lucia": "LC",
        "Saint Martin": "MF",
        "Saint Pierre and Miquelon": "PM",
        "Saint Vincent and the Grenadines": "VC",
        "Samoa": "WS",
        "San Marino": "SM",
        "Sao Tome and Principe": "ST",
        "Saudi Arabia": "SA",
        "Senegal": "SN",
        "Serbia": "RS",
        "Seychelles": "SC",
        "Sierra Leone": "SL",
        "Singapore": "SG",
        "Slovakia": "SK",
        "Slovenia": "SI",
        "Solomon Islands": "SB",
        "Somalia": "SO",
        "South Africa": "ZA",
        "South Korea": "KR",
        "Spain": "ES",
        "Sri Lanka": "LK",
        "Sudan": "SD",
        "Suriname": "SR",
        "Svalbard and Jan Mayen": "SJ",
        "Swaziland": "SZ",
        "Sweden": "SE",
        "Switzerland": "CH",
        "Syria": "SY",
        "Taiwan": "TW",
        "Tajikistan": "TJ",
        "Tanzania": "TZ",
        "Thailand": "TH",
        "Togo": "TG",
        "Tonga": "TO",
        "Trinidad and Tobago": "TT",
        "Tunisia": "TN",
        "Turkey": "TR",
        "Turkmenistan": "TM",
        "Turks and Caicos Islands": "TC",
        "Tuvalu": "TV",
        "U.S. Virgin Islands": "VI",
        "Uganda": "UG",
        "Ukraine": "UA",
        "United Arab Emirates": "AE",
        "United Kingdom": "GB",
        "United States": "US",
        "Uruguay": "UY",
        "Uzbekistan": "UZ",
        "Vanuatu": "VU",
        "Vatican": "VA",
        "Venezuela": "VE",
        "Vietnam": "VN",
        "Wallis and Futuna": "WF",
        "Western Sahara": "EH",
        "Yemen": "YE",
        "Zambia": "ZM",
        "Zimbabwe": "ZW"
        },
    }
    
    RequestType=["GET","POST"]
    
    def __init__(self,session=None):
    
        self.debugFlag= False
        self.interpalsMainUrl=u"https://www.interpals.net"
        self.interpalsAllUsersUrl=u"https://www.interpals.net/app/search"
        self.interpalsLoginUrl=u"https://www.interpals.net/app/auth/login"
        self.interpalsAccountUrl=u"https://www.interpals.net/app/account"
        
        self.yourInterpalsLogin= self.LOGIN
        self.yourInterpalsPassword= self.PASSWORD
        if len(self.yourInterpalsLogin)==0 or len(self.yourInterpalsPassword) ==0:
            raise ValueError("LOGIN or PASSWORD must not be empty!!!")        
        
        self.session=None
        self.createSession()
        
    
    
    def createSession(self):
        reqPostHeaders= {
            'host':'www.interpals.net',
            'method':'POST',
            'path':'/app/auth/login',
            'scheme':'https',
            'version':'HTTP/1.1',
            'accept':'text/html;application/xhtml+xml;application/xml;q=0.9,image/webp;*/*;q=0.8',
            'accept-encoding':'gzip, deflate',
            'content-length':'88',
            'content-type':'application/x-www-form-urlencoded',
            'origin':'https://www.interpals.net',
            'referer':'https://www.interpals.net/app',
            'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
            'upgrade-insecure-requests':'1',
        }
        
        reqGetHeaders= {
            'host':'www.interpals.net',
            'method':'GET',
            'path':'/',
            'scheme':'https',
            'version':'HTTP/1.1',
            'accept':'text/html;application/xhtml+xml;application/xml;q=0.9,image/webp;*/*;q=0.8',
            'accept-encoding':'gzip, deflate',
            'content-type':'application/x-www-form-urlencoded',
            'origin':'https://www.interpals.net',
            'referer':'https://www.interpals.net/app',
            'User-Agent' : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36',
            'upgrade-insecure-requests':'1',
        }
        
        formData=   {
            'username':self.yourInterpalsLogin,
            'auto_login':'1',
            'password':self.yourInterpalsPassword,
            'csrf_token':None # will be obtained from meta property
        }
        try:
            print("-----------Creates session ... ---------")
            self.session = requests.Session()
            r=self.makeRequestOrException("GET",url=self.interpalsMainUrl)
            content = BeautifulSoup(r.content, "html5lib")
            csrfToken= content.find(attrs={'name':'csrf-token'})
            formData['csrf_token']=csrfToken["content"]
            rPost=self.makeRequestOrException("POST",url=self.interpalsLoginUrl,**{'data':formData,'headers':reqPostHeaders})
            if self.debugFlag:
                print(self.session.cookies)
                with open("contentPOST.txt",'wb') as f:
                    f.write(rPost.content)
                
        except requests.exceptions.RequestException as exception:
            print("[ERROR] - Exception occured %s "%exception )
            sys.exit(1)
    
    def makeRequestOrException(self,reqType:RequestType,url,**kwargs):
        if len(url)==0 or url==None:
            raise ValueError("Incorrect url %s"%url)
        if not reqType in self.RequestType:
            raise ValueError("Incorrect reqType %s"%reqType)
        if self.session is None:
            raise ValueError("Session None")
        if reqType =="GET":
            r = self.session.get(url,timeout=10)
        elif reqType =="POST":
            r = self.session.post(url,timeout=10,data=kwargs['data'],headers=kwargs['headers']) 
        if(r.status_code is not 200):
            raise ValueError("Cannot make the request to %s"%url)
        return r   
            

    def isLoggedIn(self):
        if(self.session is not None):           
            r = self.session.get(self.interpalsAccountUrl,timeout=10)
            if(r.status_code is not 200):
                raise requests.exceptions.RequestException(self.interpalsAccountUrl+" 404 ")      
            if(re.search("My Home",r.text)):
                return True
        return False


    def openAccountPage(self):
        try:
            print("-----------opening account page------------")
            r=self.makeRequestOrException("GET",url=self.interpalsAccountUrl,timeout=10)  
            html = BeautifulSoup(r.content, 'html5lib')
            if self.debugFlag:
                print(html.encode('utf-8'))
                with open("contentGET.txt",'wb') as f:
                    f.write(r.content)
        except requests.exceptions.RequestException as exception:
            print("[ERROR] - Exception occured %s "%exception )
        
   
    def visitFilteredUsersProfile(self,minAge=MIN_AGE,maxAge=MAX_AGE,sex=SEX,continent=CONTINENTS,country=COUNTRY):
        '''visits profiles of all chosen range of users'''
        try:
            if not self.isLoggedIn():
                print("You are not logged on!")
                return
            print("-----------opening people's page------------")
            if minAge < 16 or minAge > 110 or maxAge < 16 or maxAge > 110:
                raise ValueError("Incorrect age value {16-100} allowed")
            if sex not in self.RequestAttributes["SEX"]:
                raise ValueError("Incorrect sex value {F,M,MF} allowed")
            else:
               sex=self.RequestAttributes["SEX"][sex]
               print(sex)
            if country != "" and country in self.RequestAttributes["COUNTRY"]:
               query = self.interpalsAllUsersUrl+"?age1=%d&age2=%d&sex=%s&sort=last_login&countries=%s"%(minAge,maxAge,sex,self.RequestAttributes["COUNTRY"][country])
               print(country)
            else:
               if continent not in self.RequestAttributes["CONTINENT"]:
                   raise ValueError("Incorrect continent value {NA, AS, EU, OC, SA,AF} allowed")
               print(continent)
               query = self.interpalsAllUsersUrl+"?age1=%d&age2=%d&sex=%s&sort=last_login&continents=%s"%(minAge,maxAge,sex,self.RequestAttributes["CONTINENT"][continent])
            r = self.makeRequestOrException("GET",url=query,timeout=10)
            print("opened  '"+ query+"' succesfully!")
            #print(r.content)
            while True:
                profiles = re.findall(r'''<a title="View profile" href="([/?\w\d;_=&%-]*)"><i class="fa fa-fw fa-user">''',r.text, re.M)
                for profile in profiles:
                    name = re.search(r'^(/\w*)?', profile,re.I)
                    rr = self.makeRequestOrException("GET",url=self.interpalsMainUrl+name.group(0),timeout=10)
                    print(name.group(0))                    
                    if self.debugFlag:
                        with open("viewedUsers.txt",'a') as f:
                            f.write(self.interpalsMainUrl+name.group(0))
                            f.write("\n")
                try:
                    nextPage = re.search(r'''<a class="cur_page" href=["/?\w\d\s;_=&%-]*>\d+ </a>\s*<a href="(["/?\w\d\s;_=&%-]*)" offset="\d+">\d+ </a>''',r.text, re.M).group(1).replace("amp;", "")
                    if self.debugFlag:
                        print(self.interpalsMainUrl+nextPage)
                except:
                    break
                r = self.makeRequestOrException("GET",url=self.interpalsMainUrl+nextPage,timeout=10)
        except requests.exceptions.RequestException as exception:
            print("[ERROR] - Exception occured %s "%exception )


    def sendMessage(self, userName, msgContent="Hi! This is my Bot writing, how are you : )?"):
        '''method taht allows you to send a message to a given user'''
        if not self.isLoggedIn():
            print("You are not logged on!")
            return
        if len(userName) == 0 or userName == None:
            return
        reqPostHeaders = {
            'host':'www.interpals.net',
            'method':'POST',
            'path':'/pm.php',
            'scheme':'https',
            'version':'HTTP/1.1',
            'accept':'application/json, text/javascript, */*; q=0.01',
            'accept-encoding':'gzip, deflate',
            'content-type':'application/x-www-form-urlencoded; charset=UTF-8',
            'origin':'https://www.interpals.net',
            'referer':None,
            'x-requested-with':'XMLHttpRequest',
        }
        formData=   {
            'action':'send_message',
            'thread': None,
            'message':msgContent
        }
        try:
            r = self.makeRequestOrException("GET",url=self.interpalsMainUrl+"/"+userName,timeout=10)
            pmMsgUrl =re.findall(r'(pm.php\?action=send&.*uid=(\d*))',r.text, re.M)
            r = self.makeRequestOrException("GET",url=self.interpalsMainUrl+"/"+"pm.php?action=send&uid=%s"%pmMsgUrl[0][1], timeout=10)
            if self.debugFlag:
                with open("contentGET.txt",'wb') as f:
                    f.write(r.content)
            threadId = re.findall(r'(name="send_thread_id"\s*value="(\d*)")', r.text, re.M)[0][1]
            #print(threadId)
            refUrl = "https://www.interpals.net/pm.php?thread_id=%s"%threadId
            reqPostHeaders['referer']=refUrl
            formData['thread']=threadId
            rPost = self.makeRequestOrException("POST",url=refUrl,**{'data':formData,'headers':reqPostHeaders})
            print("[SUCCESS] - Message: \"%s\" to user: userName has been sent correctly! "%msgContent)
        except requests.exceptions.RequestException as exception:
            print("[ERROR] - Exception occured %s "%exception )

    
    def commentProfilePhoto(self,userName,commentContent="Super photo!"):
        '''method responsible for commenting profile photos of given user'''
        if not self.isLoggedIn():
            print("You are not logged on!")
            return
        if len(userName) == 0 or userName == None:
            return
        reqPostHeaders= {
            'host':'www.interpals.net',
            'method':'POST',
            'path':None,
            'scheme':'https',
            'version':'HTTP/1.1',
            'accept':'application/json, text/javascript, */*; q=0.01',
            'accept-encoding':'gzip, deflate',
            'accept-language':'pl-PL;pl;q=0.8;en-US;q=0.6;en;q=0.4',
            'content-type':'application/x-www-form-urlencoded; charset=UTF-8',
            'origin':'https://www.interpals.net',
            'referer': None,
            'x-requested-with':'XMLHttpRequest',
            'user-agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36'
        }
        formData=   {
            'todo':'post_comment',
            'pid': None,
            'uid': '',
            'aid': None,
            'msg':commentContent
        }
        try:
            r=self.makeRequestOrException("GET",url=self.interpalsMainUrl+"/"+userName,timeout=10)
            urlParsed =re.findall(r'''(id="profPhotos"\s*>\s*<a\s*href=\s*'\s*(photo.php[?]pid=[\w*&?=?]*aid=(\d*))')''',r.text, re.M)
            #print(urlParsed )
            profPhotoUrl=urlParsed[0][1]
            aid=urlParsed[0][2]
            #print(profPhotoUrl)
            r=self.makeRequestOrException("GET",url=self.interpalsMainUrl+"/"+profPhotoUrl,timeout=10)
            path=re.findall(r'''(action="\s*(photo.php[?]pid=(\d*)[\w*&?=?#?]*)")''',r.text, re.M)[0]           
            pid=path[2]
            path=path[1]
            #print(path+ ",  pid="+pid)
            refUrl="https://www.interpals.net/photo.php?pid=%s"%pid
            reqPostHeaders['referer']=refUrl
            reqPostHeaders['path']=path
            formData['pid']=pid
            formData['aid']=aid
            rPost=self.makeRequestOrException("POST",url=refUrl,**{'data':formData,'headers':reqPostHeaders})
        except requests.exceptions.RequestException as exception:
            print("[ERROR] - Exception occured %s "%exception )
            
            

            
if __name__ == '__main__':
    try:
        crawler  = InterpalsBot()
        #crawler.visitFilteredUsersProfile()
        crawler.sendMessage("lukasz6", "Best regards from PL!")
        #crawler.commentProfilePhoto("UserName")        
        print("--done--")
    except Exception as e:
        print(e)
        print("--failed--")

        
        
        
        

#Example query   
'''   
"https://www.interpals.net/app/search?age1=16&age2=110&sex=MALE&sort=last_login&continents[0]=EU&continents[1]=NA"         
'''
 
#Example login post http request  
'''
General:
Request URL:https://www.interpals.net/app/auth/login
Request Method:POST
Status Code:302 Found
Remote Address:104.20.38.200:443

Response Headers:
cache-control:no-cache
cache-control:no-store, no-cache, must-revalidate, post-check=0, pre-check=0
cf-ray:299d9210d4a42ab5-WAW
content-type:text/html; charset=UTF-8
date:Tue, 26 Apr 2016 22:46:25 GMT
expires:Thu, 19 Nov 1981 08:52:00 GMT
location:/account.php
pragma:no-cache
server:cloudflare-nginx
set-cookie:interpals_sessid=br5m4od1vpgcmdemg7hqhmpih3; expires=Fri, 28-Jun-2019 08:33:03 GMT; Max-Age=99999999; path=/; domain=.interpals.net; HttpOnly
set-cookie:lt=523614717085548544%2Ce0400696d7d3fc30f08a08268b27b84c856287d8d0f7b00e09bd1452f1f815b7%2Cd1acbe32e07e89712f93b0828883f9d4; expires=Fri, 20-May-2016 22:46:24 GMT; Max-Age=2073600; path=/; domain=.interpals.net; httponly
status:302 Found
version:HTTP/1.1
x-powered-by:PHP/5.6.20

Request Headers:
:host:www.interpals.net
:method:POST
:path:/app/auth/login
:scheme:https
:version:HTTP/1.1
accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
accept-encoding:gzip, deflate
accept-language:pl-PL,pl;q=0.8,en-US;q=0.6,en;q=0.4
cache-control:max-age=0
content-length:88
content-type:application/x-www-form-urlencoded
cookie:resolution=1680x1050; resolution=1680x1050; resolution=1680x1050; __ubic1=MTc0NTE0MTIyODU3MWZhOWU4MDRhZWU2Ljc0NjkwOTg1; fbnl=1; __cfduid=d5d68b1068e3f3e1d47d74406665a7a3d1461710723; interpals_sessid=7ltbgiqpj1q9enb89jt0b5amp2; csrf_cookieV2=3MikEHI1Htg%3D; resolution=1680x1050; __utmt=1; __utma=46363135.695731205.1461710725.1461710725.1461710725.1; __utmb=46363135.2.9.1461710725; __utmc=46363135; __utmz=46363135.1461710725.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none); __gads=ID=9299f22b822e0d8f:T=1461710724:S=ALNI_MYo6D4j3po3DcW24Tz-eJitdgqETQ
origin:https://www.interpals.net
referer:https://www.interpals.net/index.php
upgrade-insecure-requests:1
user-agent:Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36

Form Data:
username:myname@gmail.com
auto_login:1
password:mypassword
csrf_token:lIdYyR/w95k=

'''