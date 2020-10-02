#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import re
import sys
import argparse
import json
from settings import *

is_debug = True

output_json_data = {}
result_vulner_cnt = 0
result_file_cnt = 0
regex_dynamic_sources = ''
regex_dynamic_sources_arr = []
vulner_id = 0


# Read badfunctions, securefunctins, sources from .conf files
def read_info_from_conf_files():
    # Read from sources.conf
    global regex_dynamic_sources
    global regex_dynamic_sources_arr
    text_file = open("conf/sources.conf", "r")
    lines = text_file.readlines()
    str_tmp = ''
    for line in lines:
        line = line.strip()
        line = line.replace('"', '')
        line = line.replace("'", '')
        regex_dynamic_sources_arr.append(line)
        if len(str_tmp) > 0:
            str_tmp = str_tmp + '|'
        str_tmp = str_tmp + '\\' + line + '\\[.*?\\]'
    if len(str_tmp) > 0:
        regex_dynamic_sources = '\\((.*?)(' + str_tmp + ')(.*?)\\)'
    # later more
    regex_dynamic_sources = '\\((.*?)(\\$_GET\\[.*?\\]|\\$_FILES\\[.*?\\]|\\$_POST\\[.*?\\]|\\$_REQUEST\\[.*?\\]|\\$_COOKIES\\[.*?\\]|\\$_SESSION\\[.*?\\]|\\$(?!this|e-)[a-zA-Z0-9_,]*)(.*?)\\)'


# Search the line declared
def search_decl_line(declaration, file_content):
    content = file_content.split('\n')
    for i in range(len(content)):
        if declaration in content[i]:
            return i
    return -1


# Search the line of vulnerability
def search_vulnerability_line(pattern, vulnerability, file_content):
    content = file_content.split('\n')
    for i in range(len(content)):
        vulner_code = "%s(%s%s%s)" % (pattern[0], vulnerability[0], vulnerability[1], vulnerability[2])
        if vulner_code in content[i]:
            column = content[i].find(vulner_code) + 1
            return i - 1, column
    return -1, -1


# Make clean the source code
def make_clean_source(file_content):
    # Clean up - replace tab by space
    content = file_content.replace("    ", " ")

    # echo "XXX" -> echo("XXX")
    content = content.replace("echo ", "echo(")
    content = content.replace(";", ");")
    return content


# Check if contains dynamic sources
# "$_GET", "$_POST", # "$_COOKIE", # "$_REQUEST", ...
def check_is_contain_dynamic_sources(match):
    global regex_dynamic_sources_arr
    for item in regex_dynamic_sources_arr:
        if item in match:
            return True
    return False


# Regex 3 is a predefined list of keywords such as ('htmlspecialchars', 'htmlentities')
# pattern: would be ('htmlspecialchars', 'htmlentities')
# match: declaration of variable
def check_is_secure_protected(pattern, match):
    for protection in pattern:
        if protection in "".join(match):
            return True
    return False


# Check the declaration of this variable
def check_declaration_of_this_var(file_content, vuln, path):
    # get all include, require files to check its file_content
    regex_decl = re.compile("(include.*?|require.*?)\\([\"\'](.*?)[\"\']\\)")
    include_files = regex_decl.findall(file_content)

    for include_file in include_files:
        relative_include_file = os.path.dirname(path) + "/"
        try:
            path_include_file = relative_include_file + include_file[1]
            with open(path_include_file, 'r') as f:
                file_content = f.read() + file_content
        except Exception as e:
            return False, "", ""

    vulnerability = vuln[1:].replace(')', '\\)').replace('(', '\\(')
    regex_decl2 = re.compile("\\$(.*?)([\t ]*)as(?!=)([\t ]*)\\$" + vulnerability)
    declaration2 = regex_decl2.findall(file_content)
    if len(declaration2) > 0:
        return check_declaration_of_this_var(file_content, "$" + declaration2[0][0], path)

    # $var = $_GET['var']
    regex_decl = re.compile("\\$" + vulnerability + "([\t ]*)=(?!=)(.*)")
    declaration = regex_decl.findall(file_content)
    declaration3 = path

    if len(declaration) > 0:

        # Check if constant
        decl_text = "$" + vulnerability + declaration[0][0] + "=" + declaration[0][1]
        line_declaration = search_decl_line(decl_text, file_content)
        regex_constant = re.compile("\\$" + vuln[1:] + "([\t ]*)=[\t ]*?([\"\'(]*?[a-zA-Z0-9{}_\\(\\)@\\.,!: ]*?[\"\')]*?);")
        is_vulnerable = regex_constant.match(decl_text)
        if '4' not in declaration3:
            return True, "", ""

        if is_vulnerable:
            return True, "", ""
        return False, decl_text, line_declaration

    return False, "", ""


# process a php file
def process_file(path, report_type, report_file):
    global result_vulner_cnt
    global result_file_cnt
    result_file_cnt += 1
    with open(path, 'r', encoding='utf-8', errors='replace') as content_file:

        # make clean code for better parsing
        content = content_file.read()
        content = make_clean_source(content)

        # detect vulnerability
        for pattern in patterns:
            regex = re.compile(pattern[0] + regex_dynamic_sources)
            matches = regex.findall(content)

            for vuln_content in matches:
                # check if it is protected, when vulnerability detected
                if not check_is_secure_protected(pattern[1], vuln_content):
                    decl_text, line = "", ""

                    # process multiple variable in a single line/function
                    sentence = "".join(vuln_content)
                    regex = re.compile(regex_dynamic_sources[2:-2]) # because this is not the case - for ex: echo(...)
                    for vulnerable_var in regex.findall(sentence):
                        is_vulnerable = False

                        if not check_is_contain_dynamic_sources(vulnerable_var[1]):
                            is_vulnerable, decl_text, line = check_declaration_of_this_var(
                                content,
                                vulnerable_var[1],
                                path)

                            is_secure_protected = check_is_secure_protected(pattern[1], decl_text)
                            is_vulnerable = is_secure_protected if is_secure_protected else is_vulnerable

                        # Output vuln
                        line_vuln, column = search_vulnerability_line(pattern, vuln_content, content)

                        if "$_" not in vulnerable_var[1]:
                            if "$" not in decl_text.replace(vulnerable_var[1], ''):
                                is_vulnerable = True

                        if not is_vulnerable:
                            result_vulner_cnt = result_vulner_cnt + 1
                            output_result(path, pattern, vuln_content, line_vuln, column, decl_text, line)


# process all files in dir
def process_dir(dir, extensions, report_type, report_file, current_progress):
    extensions_splited = extensions.split(',')
    extension_arr = []
    for extension in extensions_splited:
        extension_arr.append('.' + extension.strip())

    current_progress += 1
    current_progress_character = '⬛'

    try:
        for name in os.listdir(dir):

            print('\tProgress : ' + current_progress_character * current_progress + '\r', end="\r"),

            if os.path.isfile(os.path.join(dir, name)):
                for extension in extension_arr:
                    if name.endswith(extension):
                        process_file(dir + "/" + name, report_type, report_file)
            else:
                process_dir(dir + "/" + name, extensions, report_type, report_file, current_progress)

    except OSError as e:
        print("Error Occurred, maybe you need more right ?" + " " * 30)
        exit(-1)


# Output the found vulnerability information into console and json
def output_result(path, pattern, vulnerability, line, column, decl_text, decl_line):
    global vulner_id
    vulner_id += 1

    vuln = "{}({})".format(pattern[0], "".join(vulnerability))
    msg = "Potential %s vulnerability identified on %s" % (pattern[2], pattern[0])

    # Print to console
    # | 1 | / opt / test / case4.php | 6 | 2 | Potential Cross - site Scripting vulnerability identified with $var on echo | Cross-site Scripting |
    if is_debug:
        print("| %d | %s | %d | %d | %s | %s | %s " % (vulner_id, path, line + 2, column, msg, pattern[2], vuln))
    else:
        print("| %d | %s | %d | %d | %s | %s |" % (vulner_id, path, line + 2, column, msg, pattern[2]))

    print("---" * 70)

    # Print to Json
    # EXAMPLE JSON OUTPUT
    #
    # {
    # "vulnId": 1
    # "file": "\/case4.php",
    # "line": 7,
    # "column": 6,
    # "message": "Potential Cross-site Scripting vulnerability identified with $var on echo",
    # "vulnType": "Cross-site Scripting"
    # },
    if args.report_type.lower() == 'json':
        global output_json_data
        output_json_data['result'].append({
            "vulnId": vulner_id,
            "file": path,
            "line": line + 2,
            "column": column,
            "message": msg,
            "vulnType": pattern[2]
        })


# python3 phpcode_scanner.py --extensions=php,inc,php3 --target=/path --report_type=json --report_file=report.json
if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--target', action='store', dest='target', help="Directory to analyse")
    arg_parser.add_argument('--extensions', action='store', dest='extensions', help="file extensions to analyse", default='php')
    arg_parser.add_argument('--report_type', action='store', dest='report_type', help="report file type", default='json')
    arg_parser.add_argument('--report_file', action='store', dest='report_file', help="report file path", default='report.json')

    args = arg_parser.parse_args()

    if args.target is not None:
        sys.setrecursionlimit(5000000)

        print("""Running PHP Code Scanner ...""")
        print("\nSource code path: {}".format(args.target))

        read_info_from_conf_files()

        # == == == == == == == == == == == == == == == == == == == == == == ==
        # | vulnid | file | line | column | message | vulntype |
        # == == == == == == == == == == == == == == == == == == == == == == ==
        print("== " * 70)
        print("| vulnid | file | line | column | message | vulntype |")
        print("== " * 70)

        # global output_json_data
        output_json_data['result'] = []

        if os.path.isfile(args.target):
            process_file(args.target, args.report_type, args.report_file)
        else:
            process_dir(args.target, args.extensions, args.report_type, args.report_file, 0)

        if args.report_type.lower() == 'json':
            with open(args.report_file, 'w') as outfile:
                json.dump(output_json_data, outfile)

    else:
        arg_parser.print_help()
