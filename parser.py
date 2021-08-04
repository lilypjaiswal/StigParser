# %%
import xml.etree.ElementTree as et
import logging
import pandas as pd
from typing import Union
import subprocess

# logging at level INFO
log = logging.getLogger("xml_parse")
logging.basicConfig(level=logging.INFO)

# parse the XML and get the root 
def parse_XML(xml_file):

    #print(f"Dictonary for STIG_INFO from {xml_file}")
  
    # set the root node for the tree structure
    root = et.parse(xml_file).getroot()

    # call to get_stig_info and create dictionary
    si_data_dict = get_stig_info(root)

    # call to get_vuln and create list 
    (stig_data_list, column_name_list) = get_vuln(root)

    # create a data frame of the stig information using column names
    stigs_df = pd.DataFrame(stig_data_list, columns=column_name_list)

   # contain only 2 columns check text and fix text
    fix_df = stigs_df['Check_Content'] + stigs_df['Fix_Text']
    
    fix_data_list = lambda x : x.split('\n') if ('$' in x) else '' # check for a '$' if found then split the string into multiple strings

    output = list() # final output list

    bash_script_start = '$ sudo' # what every bash script begins with (fix: may need to remove sudo)

    # loop through 'stigs_df' of joined lists 'Check_Content' & 'Fix_Text' (fix: take needed date from var... column_names)
    for combinded_list in (stigs_df['Check_Content']+stigs_df['Fix_Text']):
        output.append([x for x in fix_data_list(combinded_list) if x.startswith(bash_script_start)]) #create a new list from 'fix_data_list' output and iterate from the output checking 'bash_script_start' to see if it matches for output
    # print(output) #final out put is a list of list strings [[""]..[""]]


    # running the command
    #command = output[0][0][2::]
    for command in output:
        command = command[0][2::]
        print(f"Attempted command: {command}")
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE) #run the command 
        return_code = proc.wait() # wait to get return code to see if excecution was good (A None value indicates that the process hasn’t terminated yet.)
        for line in proc.stdout:
           pass;# print(f"stdout: {line.rstrip()}")



# create dictionary for SI_DATA
def get_stig_info(root) -> dict['str', Union[str, bool]]:
    stig_info_elem = root.find('.//STIG_INFO')
    si_data_dict = {}
    for si_data in stig_info_elem.findall("SI_DATA"):
        sid_name = si_data.find("SID_NAME").text 
        sid_data_el = si_data.find("SID_DATA")

        # not all the tags are the same within SI_DATA
        if sid_data_el is None:
            sid_data = True
        else:
            sid_data = sid_data_el.text

        si_data_dict[sid_name] = sid_data
    
    return si_data_dict

def get_vuln(root):
    vuln_elems = root.findall('.//VULN')
    stig_data_list = []
    column_names = [elem.text for elem in vuln_elems[0].findall("STIG_DATA/VULN_ATTRIBUTE")]
    #print(column_names)

    for vuln_elem in vuln_elems:
        vuln_elem_data_list = []
        for stig_attribute_data_elem in vuln_elem.findall("STIG_DATA/ATTRIBUTE_DATA"):
            if stig_attribute_data_elem is None:
                attribute_data = None
            else:
                attribute_data = stig_attribute_data_elem.text
            vuln_elem_data_list.append(attribute_data)
        stig_data_list.append(vuln_elem_data_list)
    return (stig_data_list, column_names)

def write_to_csv(data_frame):
    filename = "STIGS.csv"
    #puts everything in csv
    data_frame.to_csv(filename)
   


    
# call the file to be parsed and printed
parse_XML ("CHECKLIST_TEMPLATE_RHEL.ckl")


# %%
