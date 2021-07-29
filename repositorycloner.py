import requests
from bs4 import BeautifulSoup
import os
import tarfile
import json
from shutil import copyfile, rmtree

from requests.api import get

ANDROID_SOURCE_CODE_SITE = "https://android.googlesource.com"
AURORA_SOURCE_CODE_SITE = "https://source.codeaurora.org"
TXT_FORMAT_FOOTER = "?format=TEXT"
PARSER = 'html.parser'

def create_database_entry_from_url(url, cwd, cve_number):
    '''
        This function is downloading the desired files that represent the vulnerability,
        creates specific folder tree and use the diff file to get desired files
    '''
    if(url == "#asterisk"):
        return False
        

    cwd_safe = cwd
    cve_cwd = cwd + '/' + cve_number

    # Creation of the folder structure
    try:
        os.mkdir(cve_cwd)
    except OSError:
        print("Creation of " + cve_cwd + " has failed. Remove the " + cve_number + " folder")
    try: 
        os.mkdir(cve_cwd + '/Resilient')
        os.mkdir(cve_cwd + '/Vulnerable')
        os.mkdir(cve_cwd + '/ResilientDiff')
        os.mkdir(cve_cwd + '/VulnerableDiff')
        os.mkdir(cve_cwd + '/ProjectResilient')
        os.mkdir(cve_cwd + '/ProjectVulnerable')
    except OSError:
        print("Creation of " + cve_cwd + " substructure has failed. Remove the " + cve_number + " folder")
    try:
        webpage_content = requests.get(url)
        soup = BeautifulSoup(webpage_content.text, PARSER)
    except requests.exceptions.MissingSchema:
        print("Some problem occured")
        return None


    # Retrieving single files
    diff_part_link = soup.find('a', text='diff')

    try:
        if (AURORA_SOURCE_CODE_SITE in url):
            # success = resolve_aurora_code_site(url, cve_cwd)
            # return success
            return False
        if ("http" in diff_part_link['href']):
            if (ANDROID_SOURCE_CODE_SITE in diff_part_link['href']):
                diff_link = diff_part_link['href']
            else:
                rmtree(cve_cwd)
                return False
        diff_link = ANDROID_SOURCE_CODE_SITE + diff_part_link['href']
    except TypeError:
        return None
    
    print("ANDROID RESOLVER")
    
    diff_webpage_content = requests.get(diff_link)
    diff_soup = BeautifulSoup(diff_webpage_content.text, PARSER)

    try:
        android_whole_projects_download(diff_soup, cve_cwd, url)
    except FileNotFoundError:
        print("Problem with extracting")
        try:
            rmtree(cve_cwd + '/ProjectResilient')            
        except:
            pass
        try:
            rmtree(cve_cwd + '/ProjectVulnerable')
        except:
            pass

    diff_headers = diff_soup.find_all('pre', class_='u-pre u-monospace Diff')
    for diff in diff_headers:
        file_links = diff.find_all('a', href=True)
        if (len(file_links) == 2):
            file_name, file_content = read_file_content_from_android_url(file_links[0]['href'])
            open(cve_cwd + '/Vulnerable/' + file_name, 'w').write(file_content)
            
            file_name, file_content = read_file_content_from_android_url(file_links[1]['href'])
            open(cve_cwd + '/Resilient/' + file_name, 'w').write(file_content)
        else:
            file_name, file_content = read_file_content_from_android_url(file_links[0]['href'])
            open(cve_cwd + '/Resilient/' + file_name, 'w').write(file_content)


    # Retriving the diff fragments
    diff_headers = diff_soup.find_all('pre', class_='u-pre u-monospace Diff')
    diff_content = diff_soup.find_all('pre', class_='u-pre u-monospace Diff-unified')

    for index, diff in enumerate(diff_headers):
        file_name, before_content, after_content, file_path = read_diff_changes(diff, diff_content[index])
        open(cve_cwd + '/VulnerableDiff/' + file_name, 'w').write(before_content)
        open(cve_cwd + '/ResilientDiff/' + file_name, 'w').write(after_content)
        open(cve_cwd + '/affected_files.txt', 'a').write(file_path[2:] + '\n' )

    os.chdir(cwd_safe)

    return True


def android_whole_projects_download(website_soup, cve_cwd, webpage_url):
    # Retrieving the *.tar.gz folder with source code
    html_element_for_tgz = website_soup.find('a', text='tgz')
    tgz_link = ANDROID_SOURCE_CODE_SITE + html_element_for_tgz['href']

    # Get TGZ link
    tgz_link = tgz_link.removesuffix(".tar.gz")
    tgz_link = tgz_link[:-1]
    tgz_link += (".tar.gz")

    # Download TGZ package
    tgz_data = requests.get(tgz_link)
    open(cve_cwd + '/codeResilient.tar.gz', 'wb').write(tgz_data.content)

    # Extracting the tar.gz file to "Project Resilient" folder
    os.chdir(cve_cwd + "/ProjectResilient/")
    tar = tarfile.open(cve_cwd + '/codeResilient.tar.gz', "r:gz")
    tar.extractall()
    tar.close()

    # Getting the parent address
    url = webpage_url + "?format=JSON"
    json_text = requests.get(url=url)
    json_string = json_text.content.decode('utf-8')
    json_string = "\n".join(json_string.split("\n")[1:])
    json_values = json.loads(json_string)
    url = "/".join(webpage_url.split("/")[:-1]) + '/' + json_values['parents'][0]

    # Get the parent website
    parent_website = requests.get(url=url)
    parent_soup = BeautifulSoup(parent_website.text, PARSER)

    # Retrieving the *.tar.gz folder with source code
    html_element_for_tgz = parent_soup.find('a', text='tgz')
    tgz_link = ANDROID_SOURCE_CODE_SITE + html_element_for_tgz['href']

    # Get TGZ link
    tgz_link = tgz_link.removesuffix(".tar.gz")
    tgz_link = tgz_link[:-1]
    tgz_link += (".tar.gz")

    # Download TGZ package
    tgz_data = requests.get(tgz_link)
    open(cve_cwd + '/codeVulnerable.tar.gz', 'wb').write(tgz_data.content)

    # Extracting the tar.gz file to "Project Vulnerable" folder
    os.chdir(cve_cwd + "/ProjectVulnerable/")
    tar = tarfile.open(cve_cwd + '/codeVulnerable.tar.gz', "r:gz")
    tar.extractall()
    tar.close()



def read_diff_changes(header, content):
    file_name = ""
    
    file_path = header.find('a', href=True).text
    file_path_parts = file_path.split("/")
    file_name = file_path_parts[len(file_path_parts) - 1]

    diff_lines = content.find_all('span')
    diff_lines.pop(0)
    before_content = ""
    after_content = ""
    
    for diff_line_object in diff_lines:
        diff_line = diff_line_object.text
        if diff_line[0] == '+':
            diff_line_changed = " " + "".join(diff_line[1:])
            after_content = after_content + diff_line_changed + '\n'
        elif diff_line[0] == '-':
            diff_line_changed = " " + "".join(diff_line[1:])
            before_content = before_content + diff_line_changed + '\n'
        elif diff_line[0] == '@' and diff_line[1] == "@":
            before_content = before_content + "\n\n\n" 
            after_content = after_content + "\n\n\n"
        else:
            before_content = before_content + diff_line + '\n'
            after_content = after_content + diff_line + '\n'



    return file_name, before_content, after_content, file_path

def read_file_content_from_android_url(url):
    vulnerable_file = requests.get(ANDROID_SOURCE_CODE_SITE + url)
    file_content_soup = BeautifulSoup(vulnerable_file.text, PARSER)
    rows = file_content_soup.find_all('tr',class_='u-pre u-monospace FileContents-line')
    file_lines = []

    for index,row in enumerate(rows, start=1):
        column = row.find('td', class_='FileContents-lineContents')
        span_line = column.find_all('span')
        line = ""
        for fragment in span_line:
            line += fragment.text
        if index == len(rows):
            file_lines.append(line)
        else:
            file_lines.append(line + '\n')

    parts = url.split('/')
    filename = parts[len(parts)-1]
    file_content = ""
    for line in file_lines:
        file_content += line

    return [filename, file_content]
    

def resolve_aurora_code_site(url, cwd_path):
    print("AURORA RESOLVER")
    aurora_site_content = requests.get(url)
    aurora_site_soup = BeautifulSoup(aurora_site_content.text, PARSER)
    table = aurora_site_soup.find('table', class_='diff')
    divs = table.find_all('div')
    before_content = ""
    after_content = ""
    file_name = ""
    for div in divs:
        line = div.text
        if line.startswith("diff"):
            if (file_name != ""):
                if (before_content != ""):
                    open(cwd_path + '/VulnerableDiff/' + file_name, 'w').write(before_content)
                open(cwd_path + '/ResilientDiff/' + file_name, 'w').write(after_content)
                after_content = ""
                before_content = ""
            splits = line.split()
            file_path = splits[2]
            file_name_table = file_path.split('/')
            file_name = file_name_table[len(file_name_table) - 1]
            aurora_whole_files_download(div,cwd_path,file_name)
        elif line.startswith('+'):
            diff_line_changed = " " + "".join(line[1:])
            after_content = after_content + diff_line_changed + '\n'
        elif line.startswith('-'):
            diff_line_changed = " " + "".join(line[1:])
            before_content = before_content + diff_line_changed + '\n'
        elif line.startswith('@@'):
            after_content = after_content + "\n\n\n" + '\n'
            before_content = before_content + "\n\n\n" + '\n'
        else:
            after_content = after_content + line + '\n'
            before_content = before_content + line + '\n'

    if (before_content != ""):
        open(cwd_path + '/VulnerableDiff/' + file_name, 'w').write(before_content)
    open(cwd_path + '/ResilientDiff/' + file_name, 'w').write(after_content)
            
    return True

def aurora_whole_files_download(diff_header_part, cwd_path, file_name):
    hrefs = diff_header_part.find_all('a', href = True)
    vulnerable_href = hrefs[0]['href']
    resilient_href = hrefs[1]['href']
    vulnerable_file_url = get_aurora_file_url(vulnerable_href)
    resilient_file_url = get_aurora_file_url(resilient_href)
    vulnerable_file_content = requests.get(vulnerable_file_url)
    resilient_file_content = requests.get(resilient_file_url)
    open(cwd_path + '/Vulnerable/' + file_name, 'w').write(vulnerable_file_content.text)
    open(cwd_path + '/Resilient/' + file_name, 'w').write(resilient_file_content.text)


def get_aurora_file_url(href):
    response = requests.get(AURORA_SOURCE_CODE_SITE + href)
    site_soup = BeautifulSoup(response.text, PARSER)
    file_url = site_soup.find('a', href=True, text="plain")
    return AURORA_SOURCE_CODE_SITE + file_url['href']