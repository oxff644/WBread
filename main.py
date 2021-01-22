import re
import sys
import os
import urllib
import pathlib
import hashlib
import argparse
import ipdb
from termcolor import colored

from dataclasses import dataclass

parser = argparse.ArgumentParser(description='Log analysis start')
parser.add_argument(
    '-t', '--target_files', default="web.log", help='', required=False)
parser.add_argument(
    '-r', '--result_files', default='result.txt', help='', required=False)
parser.add_argument(
    '-i', '--ip_lists', default='ip.txt', help='', required=False)
print(colored( """
                                                                  
                                                                    
           .---.    ,---,.                                          
          /. ./|  ,'  .'  \                                   ,---, 
      .--'.  ' ;,---.' .' |  __  ,-.                        ,---.'| 
     /__./ \ : ||   |  |: |,' ,'/ /|                        |   | : 
 .--'.  '   \' .:   :  :  /'  | |' | ,---.     ,--.--.      |   | | 
/___/ \ |    ' ':   |    ; |  |   ,'/     \   /       \   ,--.__| | 
;   \  \;      :|   :     \'  :  / /    /  | .--.  .-. | /   ,'   | 
 \   ;  `      ||   |   . ||  | ' .    ' / |  \__\/: . ..   '  /  | 
  .   \    .\  ;'   :  '; |;  : | '   ;   /|  ," .--.; |'   ; |:  | 
   \   \   ' \ ||   |  | ; |  , ; '   |  / | /  /  ,.  ||   | '/  ' 
    :   '  |--" |   :   /   ---'  |   :    |;  :   .'   \   :    :| 
     \   \ ;    |   | ,'           \   \  / |  ,     .-./\   \  /   
      '---"     `----'              `----'   `--`---'     `----'    
                                                                    
""",'cyan'))
args = parser.parse_args()
ip_db = ipdb.District("ipipfree.ipdb")

result_files, target_files, ip_lists = pathlib.Path(
    args.result_files), pathlib.Path(args.target_files), pathlib.Path(
        args.ip_lists)
if not target_files.exists():
    print('file not exists!')
    exit()

rules = {
    'XSS': {
        'XSS':
        r'<(?:javascript|script|img|object|style|div|table|iframe|meta|body|svg|embed|a|input|marquee|link|xml|image|html).*(?:alert|onerror|document\.write|onload|onfocus|prompt|confirm)',
    },
    'SQL Injection': {
        'SQL注入':
        r'(?:select|and+?|dbms|drop|alert|upper|or 1=1|union|convert|contact|echo|version|sysdatabase|insert|information_schema|if|preg_\w+|execute|echo|print|print_r|var_dump|(fp)open|eval|file_get_contents|include|require|require_once|shell_exec|phpinfo|system|passthru|\(?:define|base64_decode\(|group\s+by.+\(|%20or%20|%20and%20|sleep|delay|nvarchar|exec|chr\(|concat|%bf|sleep\((\s*)(\d*)(\s*)\)|current|having|database)',
    },
    'XXE': {
        '外部实体注入': r'(<\?xml.*\?>|<!.*>|<xsl.*>)',
    },
    'ldap': {
        'LDAP': r'\*[\(\)|]+',
    },
    'ArbitraryFileOperation': {
        '任意文件读取包含': r'[.]+\\',
    },
    'ArbitraryCodeExcute': {
        '任意代码执行':
        r'(=.*phpinfo|=.*php://|=.*\$_post\[|=.*\$_get\[|=.*\$_server\[|=.*exec\(|=.*system\(|=.*call_user_func|=.*passthru\(|=.*eval\(|=.*execute\(|=.*shell_exec\(|=.*file_get_contents\(|=.*xp_cmdshell|=.*array_map\(|=.*create_function\|=.*unserialize\(|=.*echo\()',
    },
    'jbossvuln': {
        'jboss':
        r'(?:jmx-console|web-console|jbossmq-httpli|/invoker/readonly|invoker)',
    },
    'struts2vuln': {
        'struct2':
        r'xwork.MethodAccessor.denyMethodExecution|_memberAccess.*ServletActionContextredirect:.*context.get|xwork2.dispatcher.HttpServletRequest|@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS',
    },
    'dirtraversal': {
        '路径穿越': r'etc.*?passwd|etc.*?shadow|etc.*?hosts|.htaccess|.bash_history',
    },
    'sen': {
        'sen':
        r'\.{2,}|%2e{2,}|%252e{2,}|%uff0e{2,}0x2e{2,}|\./|\{FILE\}|%00+|json|\.shtml|\.pl|\.sh|\.do|\.action|zabbix|phpinfo|/var/|/opt/|/local/|/etc|/apache/|\.log|invest\b|\.xml|apple-touch-icon-152x152|\.zip|\.rar|\.asp\b|\.php|\.bak|\.tar\.gz|\bphpmyadmin\b|admin|\.exe|\.7z|\.zip|\battachments\b|\bupimg\b|uploadfiles|templets|template|data\b|forumdata|includes|cache|jmxinvokerservlet|vhost|bbs|host|wwwroot|\bsite\b|root|hytop|flashfxp|bak|old|mdb|sql|backup|^java$|class',
    },
    'dangerous request': {
        '不安全的HTTP请求':
        r'("put.*http/1.|"options.*http/1.|"delete.*http/1.|"move.*http/1.|"trace.*http/1.|"copy.*http/1.|"connect.*http/1.|"propfind.*http/1.)',
    }
}


def func_md5(data: str):
    """
        计算hash值
    """
    return hashlib.new('md5', data.encode()).hexdigest()


# 整理后的规则池
rule_pool = {}
for key, items in rules.items():
    for name, code in items.items():
        rule_pool[func_md5(f'{key}-{name}')] = (key, name,
                                                re.compile(code, re.I), code)


def analysis(log_file: pathlib.Path, res_file: pathlib.Path) -> None:
    """
        日志分析方法
    """

    with log_file.open('r') as logs:
        datas = {}
        for line in logs:
            ip_data = None
            for (key, name, rule, code) in rule_pool.values():
                matched = rule.search(line)
                if not matched:
                    continue
                if not ip_data:
                    ip_data = IP_analysis.analysis_ip(line)

                msg = f'[*]IP地址:{ip_data} \t[!]漏洞类型: {key}\t[+]漏洞细节: {name}\t\n'
                code = func_md5(msg)
                
                if code not in datas:
                    datas[code] = [msg, 0]
                    print(colored(msg,'red'))
                datas[code][-1] += 1

        with res_file.open('a') as out:
            out.write('\n'.join([_[0] for _ in datas.values()]))


@dataclass
class IP_analysis:
    @staticmethod
    def analysis_ip(line: str) -> str:
        """
            IP分析方法
        """
        return IP_analysis.fetch_ip(line)

    @staticmethod
    def fetch_ip(line: str) -> str:
        """
            IP检索方法
        """
        ips = re.search(
            r'((2[0-4]\d|25[0-5]|[01]?\d\d?)\.){3}(2[0-4]\d|25[0-5]|[01]?\d\d?)',
            line)
        ip = ips.group() 
        datas = ip_db.find_map(ip, "CN")
        return f"{ip}-{datas.get('country_name','未知')}"


if __name__ == "__main__":
    analysis(target_files, result_files)
    print("Duang~Duang~ 检测完毕啦~")
