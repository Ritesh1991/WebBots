#!/usr/bin/env python
import sys
import requests
import re
import os

'''==================== USAGE ===================='''
  # 1.    config your download path [DOWNLOAD_FOLDER_PATH]  
  # 2.    fire up the script 
'''================== USAGE-END =================='''

PY2 = sys.version_info[0] == 2
if PY2:
    raise Exception("Please use finally Python3.x version :)")

DOWNLOAD_FOLDER_PATH= "L:\EBOOKS\Allitebooks"  


class AllItEbooksDownloader():
   
    def __init__(self):
        self.downloadPath=os.path.join(DOWNLOAD_FOLDER_PATH)
        if not os.path.exists(self.downloadPath):
            raise ValueError("There is no such folder under %s"%self.downloadPath)
        self.session = requests.Session()
                
    def _makeGetRequestOrException(self,url):
        if len(url)==0 or url==None:
            raise ValueError("Incorrect url %s"%url)
        r = self.session.get(url,timeout=10)       
        if(r.status_code is not 200):
            raise ValueError("Cannot make the request to %s"%url)
        return r   
            

    def _openPage(self,pageNr):
        html =None
        try:
            print("-----------opening account page------------")
            url= "http://www.allitebooks.com/page/%s"%pageNr
            r=self._makeGetRequestOrException(url)             
        except requests.exceptions.RequestException as exception:
            print("[ERROR] - Exception occured %s "%exception )
        return r.text
    
    def _getNrOfPages(self):
        html =self._openPage('1')
        reg= re.compile(r'<span class="pages">1\s*/\s*(\w+)\s*Pages</span>')       
        nrOfPages= reg.search(html)
        if nrOfPages is not None:
            pages= int(nrOfPages.group(1))
            print("-----------found %s pages------------"%pages)
            return pages
        else:
            raise ValueError("Nr of pages not found, something went wrong!")
    
    def _searchForTitles(self, html):
        if html is None:
            return None
        print("-----------searching for title------------")
        reg= re.compile(r'<h2 class="entry-title"><a href="([\w+://.-]*)" rel="bookmark">([\w+\s*://.-]*)')       
        books= reg.findall(html)
        return books
        
    def _getDownloadLink(self, html):
        if html is None:
            return None
        reg= re.compile(r'<span class="download-links">\s*<a href="([\s*\w+://.-]*)"\s*target')       
        downloadLink= reg.search(html)
        if downloadLink is not None:
            #print(downloadLink.group(1))
            return downloadLink.group(1)
        return None
    
    def downloadEbook(self,title,url):
        for ch in ['?',':','*','/','\\']:
            if ch in title:
                title=title.replace(ch,'-')
        fullFilePath=os.path.join(self.downloadPath,title+'.pdf')
        if(os.path.isfile(fullFilePath)):
            print(fullFilePath+" already exists")
            return False
        if url is not None:
            pdf=self._makeGetRequestOrException(url)
            if(pdf.status_code is 200):
                with open(fullFilePath,'wb') as f:
                    f.write(pdf.content)
                    print("[INFO]: "+ "Ebook:  %s.pdf  downloaded"%title)
                return True
        return False
           
    def downloadAll(self):
        nrOfPages= self._getNrOfPages()
        for page in range(1,nrOfPages):
            books=self._searchForTitles(self._openPage(page))
            for book in books:
                r=self._makeGetRequestOrException(book[0])
                if(r.status_code is 200):
                    downloadUrl=self._getDownloadLink(r.text)
                    self.downloadEbook(book[1],downloadUrl)
                                       
if __name__ == '__main__':
    try:
        downloader  = AllItEbooksDownloader()
        downloader.downloadAll()      
        print("[INFO]: --done--")
    except Exception as e:
        print(e)
        print("--failed--")

        
        
        
 