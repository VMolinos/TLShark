# TLShark functions

# LIBRARIES:
###------------------------------------------------------------------------------------------------------------------------------------
import os
import ssl
import copy
import psutil
import hashlib
import textwrap
import subprocess
import shutil as sh
import asn1crypto.x509 as asn1


# LOCATIONS    
###------------------------------------------------------------------------------------------------------------------------------------
json_path ="./tlshark_json/" # json folder path.
tmp_tlshark_path = "/tmp/tlshark_tmp" # tlshark temporal folder.
tmp_captured_path = tmp_tlshark_path + "/captured_certs/" # Captured certificates temporal folder.
tmp_cloned_path = tmp_tlshark_path + "/cloned_certs/" # Cloned certificates temporal folder.



# COLORS
###------------------------------------------------------------------------------------------------------------------------------------
def colors(color,under):
    """Colors function: 
        * Operation: defines a bold color palette.
        * Function used by the following functions: info, operating_modes, coloring, store_cert, cert_info.

        * Input arguments:
            -color: selected color. <string type>.
            -under: underlined. <int type> (0-False, 1-True).

        * Output arguments: 
            -palette[color]. <string type> (coloring command).
    """

    if under:
        palette = {
            'reset': '\033[1;4;0m',
            'grey': '\033[1;4;30m',
            'red': '\033[1;4;31m',
            'green': '\033[1;4;32m',
            'yellow': '\033[1;4;33m',
            'blue': '\033[1;4;34m',
            'purple': '\033[1;4;35m',
            'cian': '\033[1;4;36m',
            'white': '\033[1;4;37m',
        }

    else:
        palette = {
            'reset': '\033[1;0m',
            'grey': '\033[1;30m',
            'red': '\033[1;31m',
            'green': '\033[1;32m',
            'yellow': '\033[1;33m',
            'blue': '\033[1;34m',
            'purple': '\033[1;35m',
            'cian': '\033[1;36m',
            'white': '\033[1;37m',
        }
    return palette[color]




# OPERATING MODES
###------------------------------------------------------------------------------------------------------------------------------------
def operating_modes(mode,info,certs,pcap,json_mode,certfrom_mode,url):
    """Opeating modes function: 
        * Operation: prints the corresponding mode box and checks that the correct flags 
          are chosen for each mode.

        * Use the following functions: colors.

        * Input arguments:
            -mode: selected operating mode. <string type> (100 -> verbose, 010 -> cerlog or 001 -> rogue).
            -info: selected info. <string type> (-client, -server or -all).
            -certs: with or without certificate info. <bool type>.
            -pcap: with or without pcap mode. <int type> ('0'- without pcap, 'capture.pcap' - with pcap).
            -json_mode: with or without json file. <string type>.
            -certfrom_mode: selected certfrom_mode. <string type>. 
                            (100 -> certfrom mitmproxy, 010 -> certfrom tlshark, 001 -> certfrom path)
            -url: selected url. <string type>.
    """

    if mode == '100000': # Verbose mode.
        if info == '100': # Client info.
            print(colors('red',0) + "                     {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}")
            print("                     {*}         VERBOSE MODE         {*}")
            print("                     {*}    -- Only Client info --    {*}")
            if certs:
                print("                     {*}    -- With certificate --    {*}")
            if pcap:
                print("                     {*}       -- pcap  mode --       {*}")
            print("                     {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}" + colors('reset',0) + "\n\n\n")

        elif info == '010': # Server info.
            print(colors('red',0) + "                     {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}")
            print("                     {*}         VERBOSE MODE         {*}")
            print("                     {*}    -- Only Server info --    {*}")
            if certs:
                print("                     {*}    -- With certificate --    {*}")
            if pcap:
                print("                     {*}       -- pcap  mode --       {*}")
            print("                     {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}" + colors('reset',0)+ "\n\n\n")

        elif info == '001': # All info.
            print(colors('red',0) + "                     {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}")
            print("                     {*}         VERBOSE MODE         {*}")
            print("                     {*}        -- All info --        {*}")
            if certs:
                print("                     {*}    -- With certificate --    {*}")
            if pcap:
                print("                     {*}       -- pcap  mode --       {*}")
            print("                     {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}" + colors('reset',0)+ "\n\n\n")

        elif info == '000':
            print(colors('red',1) + "ERROR:" + colors('reset',1) + " You must select a type of information between -client, -server or -all." + "\n" + "       -h flag to help!")
            exit()
        
        else:
            print(colors('red',1) + "ERROR:" + colors('reset',1) + " You must select only a type of information between -client, -server or -all." + "\n" + "       -h flag to help!")
            exit()

    elif mode == '010000': # Cerlog mode.
        print(colors('red',0) + "                                    {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}")
        print("                                    {*}            CERLOG  MODE            {*}")
        print("                                    {*}   -- Impersonated Server info --   {*}")
        if pcap:
            print("                                    {*}          -- pcap  mode --          {*}")
        print("                                    {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}" + colors('reset',0) + "\n\n\n")
        
    elif mode == '001000': # Rogue mode.
        print(colors('red',0) + "      {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}")
        print("      {*}            ROGUE MODE -- IMPERSONATED SERVER            {*}")
        if json_mode:
            print("      {*}                    -- json  mode --                     {*}")
        print("      {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}" + colors('reset',0) + "\n\n\n")

    elif mode == '000100': # Transparent Mitmproxy mode.
        print(colors('red',0) + "      {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}")
        print("      {*}     TRANSPARENT MITMPROXY MODE     {*}")
        if json_mode:
            print("      {*}          -- json  mode --          {*}")
        if certfrom_mode == '100':
            print("      {*}       -- cert from tlshark --      {*}")
        
        elif certfrom_mode == '010':
            print("      {*}      -- cert from mitmproxy --     {*}")
        
        elif certfrom_mode == '001':
            print("      {*}        -- cert from path --        {*}")

        print("      {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}" + colors('reset',0) + "\n\n\n")

        if certfrom_mode == '000':
            print(colors('red',1) + "ERROR:" + colors('reset',1) + "You must select a certfrom mode." + '\n' + "       -h flag to help!")
            exit()

        elif not(certfrom_mode == '100') and not(certfrom_mode == '010') and not(certfrom_mode == '001'):
            print(colors('red',1) + "ERROR:" + colors('reset',1) + "You must select only one certfrom mode." + '\n' + "       -h flag to help!")
            exit()
            
    elif mode == '000010': # Reverse Mitmproxy mode.
        if url:
            print(colors('red',0) + "      {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}")
            print("      {*}           REVERSE MITMPROXY MODE            {*}")
            print("      {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}" + colors('reset',0) + "\n\n\n")
        else:
            print(colors('red',1) + "ERROR:" + colors('reset',1) + "You must indicate a path using the -path flag." + '\n' + "       -h flag to help!")
            exit()
            
    elif mode == '000001': # TLS Version Detector mode.
        print(colors('red',0) + "      {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}")
        print("      {*}           TLS VERSION DETECTOR MODE         {*}")
        print("      {*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}{*}" + colors('reset',0) + "\n\n\n")
        
    elif mode == '000000': 

        print(textwrap.dedent("""\

        /////////////  ////          /////////////   ///             //////////  //////////  ///     ///
            ////      ////          ////            ///                    ///  ///    ///  ///   ///
           ////      ////          //////////////  ////////////  ////////////  //////////  /// ///
          ////      ////                    ////  ///      ///  ///      ///  /// ///     ///    ///
         ////      /////////////  /////////////  ///      ///  ////////////  ///   ///   ///       ///
        -----------------------------------------------------------------------------------------------------------

                                A testing tool by Víctor M. Molinos Santiago.
                                             vmolinos@jtsec.es
                                                version 1.0
        """
        ))
        exit()

    else: 
        print(colors('red',1) + "ERROR:" + colors('reset',1)  + " You must select only one operating mode." + "\n" + "       -h flag to help!")
        exit()




# DISPLAY_FILTER_MANAGER
###------------------------------------------------------------------------------------------------------------------------------------
def display_filter_manager(info,cert,client_ip,server_ip,addr_ip,server_port):
    """Display filter manager function: 
        * Operation: defines the type of display filter to filter the packets.

        * Input arguments:
            -info: selected info in argparse -client, -server or -all. <string type>.
            -cert: with or without certificate information. <bool type>.
            -client_ip: source machine ip address. <string type>.
            -server_ip: target machine ip address. <string type>.
            -server_port: target machine tcp port. <string type>.

        * Output arguments: 
            -filter type: display filter type. <int type>.
            -display filter: display filter type. <string type>.
    """

    filter_type = 0
    display_filter = 'tls and '

    if cert: # CUSTOMER INFORMATION WITH CERTIFICATE.

        # CUSTOMER CLIENT INFORMATION WITH CERTIFICATE.
        if info == '100':
            filter_type = 4
            client_filter = 'tls.handshake.type==1'
            cert_filter = 'tls.handshake.type==11'
            
            if addr_ip:
                display_filter += 'ip.addr==' + addr_ip + ' and '
            else:
                if server_ip:
                    client_filter += ' and ip.dst==' + server_ip 
                    cert_filter += ' and ip.src==' + server_ip
                    
                if client_ip:
                    client_filter += ' and ip.src==' + client_ip
                    cert_filter += ' and ip.dst==' + client_ip

                if server_port:
                    client_filter += ' and tcp.dstport==' + server_port
                    cert_filter += ' and tcp.srcport==' + server_port
                
            display_filter += '((' + client_filter + ') or (' + cert_filter + '))'

        # CUSTOMER SERVER INFORMATION WITH CERTIFICATE.
        elif info == '010':
            filter_type = 5
            display_filter += '(tls.handshake.type==2 or tls.handshake.type==11 or tls.handshake.type==12)'

            if addr_ip:
                display_filter += ' and ip.addr==' + addr_ip 
            else:
                if server_ip:
                    display_filter += ' and ip.src==' + server_ip
                if client_ip:
                    display_filter += ' and ip.dst==' + client_ip
                if server_port:
                    display_filter += ' and tcp.srcport==' + server_port

        # CLIENT AND SERVER INFORMATION WITH CERTIFICATE.
        elif info == '001':
            filter_type = 6

            display_filter_one = 'tls.handshake.type==1' 
            display_filter_two = '(tls.handshake.type==2 or tls.handshake.type==11 or tls.handshake.type==12)'
            

            if addr_ip:
                display_filter += 'ip.addr==' + addr_ip + " and "
            else:            
                if server_ip:
                    display_filter_one += ' and ip.dst==' + server_ip 
                    display_filter_two += ' and ip.src==' + server_ip
                if client_ip:
                    display_filter_one += ' and ip.src==' + client_ip
                    display_filter_two += ' and ip.dst==' + client_ip
                if server_port:
                    display_filter_one += ' and tcp.dstport==' + server_port
                    display_filter_two += ' and tcp.srcport==' + server_port

            display_filter += '((' + display_filter_one + ') or (' + display_filter_two+ '))'


    else: # CUSTOMER INFORMATION WITHOUT CERTIFICATE.

        # CUSTOMER CLIENT INFORMATION WITHOUT CERTIFICATE.
        if info == '100':
            filter_type = 1
            display_filter += 'tls.handshake.type==1'
            
            if addr_ip:
                display_filter += ' and ip.addr==' + addr_ip
            else:
                if server_ip:
                    display_filter += ' and ip.dst==' + server_ip 
                if client_ip:
                    display_filter += ' and ip.src==' + client_ip
                if server_port:
                    display_filter += ' and tcp.dstport==' + server_port

        # CUSTOMER SERVER INFORMATION WITHOUT CERTIFICATE.
        elif info == '010':
            filter_type = 2
            display_filter += '(tls.handshake.type==2 or tls.handshake.type==12)'
            if addr_ip:
                display_filter += ' and ip.addr==' + addr_ip
            else:
                if server_ip:
                    display_filter += ' and ip.src==' + server_ip
                if client_ip:
                    display_filter += ' and ip.dst==' + client_ip
                if server_port:
                    display_filter += ' and tcp.srcport==' + server_port

        # CUSTOMER CLIENT AND SERVER INFORMATIN WITHOUT CERTIFICATE.
        elif info == '001':
            filter_type = 3
            client_filter = 'tls.handshake.type==1'
            server_filter = '(tls.handshake.type==2 or tls.handshake.type==12)'
            
            if addr_ip:
                display_filter += 'ip.addr==' + addr_ip + " and "
            else:
                if server_ip:
                    client_filter += ' and ip.dst==' + server_ip 
                    server_filter += ' and ip.src==' + server_ip
                    
                if client_ip:
                    client_filter += ' and ip.src==' + client_ip
                    server_filter += ' and ip.dst==' + client_ip

                if server_port:
                    client_filter += ' and tcp.dstport==' + server_port
                    server_filter += ' and tcp.srcport==' + server_port
                
            display_filter += '((' + client_filter + ') or (' + server_filter + '))'


    return filter_type,display_filter




# HANDSHAKE_MESSAGES
###------------------------------------------------------------------------------------------------------------------------------------
def handshake_messages(raw_packet):
    """Handsake messages function: 
        * Operation: defines the handshake messages in the raw packet.
        * Used by: basic_details.

        * Input arguments:
            -raw_packet: raw packet captured. <pyshark.packet type>.

        * Output arguments: 
            -handshake_types: types of handshake message in the raw packet. <string type>.
    """

    handshake_types = []
    if raw_packet.tls.has_field('handshake_type'):
        for field in raw_packet.tls.handshake_type.all_fields:
            handshake_types.append(field.showname_value)
        
    else:
        handshake_types = (colors('red',0) + "ERROR: " + colors('reset',0) + "TLS handshake type does not exist!")
        
    return handshake_types




#TLS_VERSIONS
###------------------------------------------------------------------------------------------------------------------------------------
def tls_versions(raw_packet):
    """TLS versions function: 
        * Operation: defines the tls versions in the raw packet.
        * Used by: basic_details.

        * Input arguments:
            -raw_packet: raw packet captured. <pyshark.packet type>.

        * Output arguments: 
            -types: types of tls version. <string type>.
    """

    versions = []

    if (raw_packet.tls.has_field('handshake_extension_type') and # There are extensions and...
        '<LayerField tls.handshake.extension.type: 43>' in str(raw_packet.tls.handshake_extension_type.all_fields)):# There is a supported_versions extension
            
        for field in raw_packet.tls.handshake_extensions_supported_version.all_fields: # For each supported version
            version = field.showname_value.split(" ")
            versions.append(version[0] + "v" + version[1])

    elif raw_packet.tls.has_field("handshake_version"): # There is a handshake version
        
        version = raw_packet.tls.handshake_version.showname_value.split(" ")
        versions.append(version[0] + "v" + version[1])
            
    elif raw_packet.tls.has_field('record_version'):
        version = raw_packet.tls.record_version.showname_value.split(" ")
        versions.append(version[0] + "v" + version[1])
        
    return versions




# BASIC_DETAILS  
###------------------------------------------------------------------------------------------------------------------------------------
def basic_details(raw_packet):
    """Basic details function: 
        * Operation: collects the data details in raw packet.
        * Use the following libraries: -
        * Use the following functions: tls_versions, handshake_messages. 

        * Input arguments:
            -raw_packet: raw packet captured. <pyshark.packet type>.

        * Output arguments: 
            -first details: dictionary with the first details. <dict type>.
            -second details: dictionary with the second details. <dict type>.
            -third details: dictionary with the third details. <dict type>.
            -f_head: list with the headers to print a table with first details. <list type>.
            -s_head: list with the headers to print a table with second details. <list type>.
            -t_head: list with the headers to print a table with third details. <list type>.
    """

    first_details = {}
    third_details = {}

    f_head = []
    t_head = []
    handshake_types = handshake_messages(raw_packet)
    
    #Collecting information
    if raw_packet.__contains__("tls"): # If it is a tls message
        if raw_packet.tls.has_field("handshake_extensions_server_name"): # If it contains "server_name" extension. 
            server_name = raw_packet.tls.handshake_extensions_server_name.showname_value
        else:
            server_name = "N/A"

        f_head.append('Server Name')
        first_details["server_name"] = server_name
        # Clarification: Is not within the extensions conditional because the value of the server_name field must always be printed.
        
        if raw_packet.tls.has_field("handshake_extension_type"): # If it contains extensions...
        
            if 'Client Hello (1)' in handshake_types: # If it contains Client Hello message
                if raw_packet.tls.has_field("handshake_extensions_supported_group"): # If it contains "supported_group" extension
                    
                    t_head.append("Elliptic groups")
                    raw_groups = raw_packet.tls.handshake_extensions_supported_group.all_fields
                    supported_groups = []
                    for k in range(len(raw_groups)):
                        supported_groups.append(raw_groups[k].showname_value)

                    third_details["elliptic_groups"] = supported_groups
                
                if raw_packet.tls.has_field("handshake_sig_hash_alg"): # If it contains "signature_hash_algorithms" extension.

                    t_head.append("Signature hash algorithms")
                    raw_algorithms = raw_packet.tls.handshake_sig_hash_alg.all_fields 

                    signature_algorithms = []
                    for k in range(len(raw_algorithms)):
                        signature_algorithms.append(raw_algorithms[k].showname_value)

                    third_details["signature_hash_algorithms"] = signature_algorithms
                    
            if ('Server Key Exchange (12)' in handshake_types): # Exists a Server Key Exchange message
                if raw_packet.tls.has_field('handshake_server_named_curve'): # If it contains 'handshake_server_named_curve' extension.

                    t_head.append("Elliptic groups")
                    curve_name = raw_packet.tls.handshake_server_named_curve.showname_value
                    third_details["elliptic_groups"] = [curve_name]
                    

                if raw_packet.tls.has_field('handshake_sig_hash_alg'): # If it contains 'handshake_sig_hash_alg' extension.

                    t_head.append("Signature hash algorithms")
                    hash_algorithm = raw_packet.tls.handshake_sig_hash_alg.showname_value
                    third_details["signature_hash_algorithms"] = [hash_algorithm]
    

    # Building the details dictionaries
    f_head.append('Source IP')
    f_head.append('Destinantion IP')
    f_head.append('Source port')
    f_head.append('Destination port')

    first_details["source_ip"] = raw_packet.ip.src.showname_value
    first_details["destination_ip"] = raw_packet.ip.dst.showname_value
    first_details["source_port"] = raw_packet[raw_packet.transport_layer].srcport.showname_value
    first_details["destination_port"] = raw_packet[raw_packet.transport_layer].dstport.showname_value

    versions = tls_versions(raw_packet)
    second_details={
        "tls_versions":versions,
        "tls_handshake_messages":handshake_types
    }  
    s_head = ['TLS Versions','TLS Handshake messages'] 

    
    # Split the name and code in third details into two different fields
    if third_details:
        aux_details = {}
        if ("signature_hash_algorithms" in third_details.keys()):
            signature_algorithms = third_details["signature_hash_algorithms"]
            sig_h_algorithms = []

            for n in signature_algorithms:
                aux1,aux2 = n.split(" (")
                code = aux2[0:6]
                algorithm = aux1[0:len(aux1)-1]
                algorithms_dic = {'code': code, 'algorithm': algorithm}
                sig_h_algorithms.append(algorithms_dic)

            if len(sig_h_algorithms) == 1:
                aux_details['signature_hash_algorithms'] = sig_h_algorithms[0]
            else:
                aux_details['signature_hash_algorithms'] = sig_h_algorithms

        if "elliptic_groups" in third_details.keys():
            supported_groups = third_details["elliptic_groups"]
            groups = []
            for n in supported_groups:
                group = n[0:len(n)-9]
                code = n[len(n)-7:len(n)-1]
                group_dic = {'code':code,'elliptic_group':group}
                groups.append(group_dic)
                
            if len(groups) == 1:
                aux_details['elliptic_groups'] = groups[0]
            else:
                aux_details['elliptic_groups'] = groups

        third_details = aux_details

    return first_details,second_details,third_details,f_head,s_head,t_head




# CIPHERMATCH
###------------------------------------------------------------------------------------------------------------------------------------
def ciphermatch(cipher_codes):
    """Ciphermatch function: 
        * Operation: Find the code of a cipher in codes column of Dictionary.
        * Use the following functions: library.
        * Function used by: match_result.

        * Input arguments:
            -CipherCodes: list of cipher codes found in the capture. <list type>. 

        * Output arguments: 
            -matches: index where the match was found. <list type>.  
            -code_error: control for "not found ciphersuite" error. <string type>
    """
   
    dic_codes = dictionary()['codes']
    matches = []
    code_error = ''
    
    for code in cipher_codes:
        if code in dic_codes:
            matches.append(dic_codes.index(code))          
            
        else:
            code_error=code

    return matches,code_error




# ORGANIZE
###------------------------------------------------------------------------------------------------------------------------------------
def organise(messy):
    """Organise function:
        * Operation: organizes the result provided by match_result by priority. R: regular, L: legacy ,NR: not regular).

        * Function used by the following functions: match_result.

        * Input arguments:
            -messy: messy result (index,). <list of lists type>.
        * Output arguments: 
            -organized: organized result. <list of lists type>.
    """
    
    aux = copy.deepcopy(messy)
    organized = []
    
    for row in messy:
        if row[1] == 'R':
            organized.append(row)
            aux.remove(row)
    
    messy = copy.deepcopy(aux)
    for row in messy:
        if row[1] == 'L':
            organized.append(row)
            aux.remove(row)
    
    organized.extend(aux)

    return organized




# COLORING
###------------------------------------------------------------------------------------------------------------------------------------
def coloring(target):
    """Coloring function: 
        * Operation: color the result. R: green, L: cian, NR: purple.

        * Function used by the following functions: result_match.
        * Use the following functions: colors.
        * Use the following libraries: numpy.

        * Input arguments:
            -target: target list of lists with uncolored cipher suites. <list of lists type>.
        * Output arguments: 
            -target: target list with colored cipher suites. <list of lists type>.
    """
    
    for row in target:
        if row[2] == 'R':
            row[0] = colors('green',0) + " " + row[0]
        elif row[2] == 'L':
            row[0] = colors('cian',0) + " " + row[0]
        else:
            row[0] = colors('purple',0) + " " + row[0] 
    
    target[len(target)-1][3] = target[len(target)-1][3] + " " + colors('reset',0)
       
    return target




# MATCH_RESULT 
###------------------------------------------------------------------------------------------------------------------------------------
def match_result(raw_packet):
    """Match result function: 
        * Operation: Extract the cipher suite codes by the packet and search it in Dictionary.txt for returns
                     the correspondign cipher suites sorted, colored and categorized.

        * Use the following functions: cipher_match, organize, coloring, dictionary.

        * Input arguments:
            -raw_packet: raw packet captured. <pyshark.packet type>.

        * Output arguments: 
            -cipher_suites: correspondign cipher suites sorted, and categorized (list of dictionaries). <list type>.
            -color_suites: correspondign cipher suites sorted, colored and categorized (list of dictionaries). <list type>.
            -ciph_head: list with the headers to print a table with cipher suites. <list type>.
            -code_error: control for "not found ciphersuite" error. <string type>
    """

    cipher_suites = raw_packet.tls.handshake_ciphersuite

    # Preparing cipher suites to match.
    cipher_codes = []
    for suite in cipher_suites.all_fields: 
        aux = suite.showname_value.split("(")
        aux = aux[1].replace(")","")
        aux = aux.upper()
        aux = aux.replace("X","x")
        cipher_codes.append(aux)
        
    # Match and organise 
    matches,code_error = ciphermatch(cipher_codes)
    dic = dictionary() 
    result = []
    if matches:
        for ind in matches:
            aux = [dic["codes"][ind], dic["categories"][ind], dic["tls_ciphers"][ind]]
            result.append(aux)
        result = organise(result)
        
        # Index
        for n,row in enumerate(result):
            row.insert(0,str(n))
    
        # Result for printing
        aux = copy.deepcopy(result)
        color_suites = coloring(aux)
        ciph_head = [colors('white',0) + "Index", "Code", "Category", "Cipher Suite" + colors('reset',0)]
    
        # Result for Json
        cipher_suites = []
        for row in result:
            code = row[1]
            category = row[2]
            cipher = row[3]
            result_dic = {'code':code,'category':category,'cipher_suite':cipher}
            cipher_suites.append(result_dic)

    else: 
        cipher_suites = '0'
        color_suites = '0'
        ciph_head = '0'
        
    return cipher_suites,color_suites,ciph_head,code_error




# EXTRACT_CERT  
###------------------------------------------------------------------------------------------------------------------------------------
def extract_cert(directory):
    """Cert extract function: 
        * Operation: Extract data from a certificate:

        * Function used by the following functions: cert_info
        * Use the following libraries: Certificate from asn1crypto.x509.

        * Input arguments:
            -directory: path of the directory where the certificate in der format. <string type>.
        * Output arguments: 
            -c_name: c_name. <string type>.
            -pk_size: public key size in bytes. <string type>.
    """

    with open(directory, "rb") as f:
        cert = asn1.Certificate.load(f.read())

    result=[]
    try:
        c_name = cert.native["tbs_certificate"]["subject"]["common_name"]
        result.append(c_name)
    except:
        result.append("There is no common name")
        pass

    pk_size = cert.public_key.bit_size
    result.append(pk_size)

    return result




# TXT EXTRACTOR
###------------------------------------------------------------------------------------------------------------------------------------
def txt_extractor(txt_list,start_word,end_word):
    """Txt extractor function: 
        * Operation: Extracts a paragraph delimited by a start word 
                     and an end word in a .txt file.

        * Use the following functions: - . 
        * Use the following libraries: - .
        * Function used by the following functions: clone_cert

        * Input arguments:
            -txt_list: List of strings. <list type>.
            -start_word: word from which it begins to copy. Copy from 
                         the beginning if start_word == ''. <string type>.
            -end_word: word from which copying is terminated. Copy to the 
                       end if end_word == ''. <string type>.

        * Output arguments:
            -paragraph: paragraf copied. <list type>
            -line_end: line where the end_word is found. <int type>
    """
    
    paragraph = []
    copy = False
    from_the_beginning = False
    to_the_end = False
    
    if not(start_word):
        from_the_beginning = True
    if not(end_word):
        to_the_end = True    

    
    if from_the_beginning:
        copy = True
    
    n = 0
    stop = False
    while not(stop) and n<len(txt_list):
        line = txt_list[n]
        
        if not(from_the_beginning) and line.startswith(start_word):
            copy = True

        if not(to_the_end) and line.startswith(end_word):
            stop = True
            
        if copy:
            paragraph.append(line)
            
        line_end = n
        n += 1
    return paragraph,line_end




# CLONE_CERT
###------------------------------------------------------------------------------------------------------------------------------------
def clone_cert(id_number):
    """Clone cert function: 
        * Operation: Use Apostille to cone the captured pem certs in Captured_folder and store it in 
                     Cloned_folder. Same CA (if exists) but different public key. If there is 
                     a single certificate it returns a single cloned certificate with its private 
                     key, if there are several certificates, then the result is a chain of cloned 
                     certificates.

        * Use the following functions: - .
        * Use the following programs: Apostille. 
        * Use the following libraries: os, subprocess.
        * Function used by the following functions: -

        * Input arguments:
            -id_number: id for the comunication. <int type>.

        * Output arguments:
            -cloned_pem_chain: cloned pem chain <string type>
    """

    # PRELIMINARS.
    conn_id = "ID_" + str(id_number) # ID for the connetion.
    clon_path = tmp_cloned_path + conn_id + "_cloned/" # Directory path for the cloned certificate

    try:
        os.mkdir(clon_path) # Generate folder in clon_path path.
    except FileExistsError: # Overwrite folder.
        sh.rmtree(clon_path)
        os.mkdir(clon_path) 

    #single = False
    orig_captured_folder = tmp_captured_path + "cerlog_captured_certs/" + conn_id # Directory folder for de original chain pem certificate.
    #n_certs = len(os.listdir(orig_captured_folder)) # Number of certificates.
    orig_path = orig_captured_folder + "/ori_chain.pem" # Path for de original chain pem certificate.
    #cert_name = "cloned_certificate"
    
    """ if n_certs > 2:
            flag = "-sc"
            single = True
        else:
            flag = "-sl"
    """


    # CLONING THE CERTIFICATES (DIFFERENT PUBLIK KEY) AND STORE IT IN ID_id_cloned FOLDER INSIDE Cloned_certificates FOLDER.
    command = "java -jar /opt/apostille/apostille-1.2-SNAPSHOT.jar " + orig_path #+ " > " + clon_path + "cloned_certificates.key+chain"
    aux = subprocess.run(command.split(" "), stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    
    
    # SEPARATING THE CLONED CHAIN FROM DE PRIVATE KEY.
    stdout = str(aux.stdout).split("\\n")

    cloned_pem_chain,n = txt_extractor(stdout, "-----END RSA PRIVATE KEY-----", "")
    cloned_pem_chain = '\n'.join(cloned_pem_chain[1:])
    
    private_key,n = txt_extractor(stdout, "", "-----END RSA PRIVATE KEY-----")
    private_key = '\n'.join(private_key)[1:]
    
    
    with open (clon_path + "cloned_certificate.pem",'w') as f:
        f.write(cloned_pem_chain)

    with open (clon_path + "cloned_certificate.key",'w') as f:
        f.write(private_key)
    
    
    """# CLONING THE CERTIFICATES (SAME CA (IF EXISTS) BUT DIFFERENT PUBLIK KEY) AND STORE IT IN ID_id_cloned FOLDER INSIDE Cloned_certificates FOLDER.
    comando = ["jackal", flag, "-c", orig_path, "-o",  clon_path + cert_name]
    aux = subprocess.run(comando, capture_output=True, text=True)


    # GENERATING A SINGLE CERTIFICATE WITH ALL PEM STRINGS AND STORE IT IN ID_id_cloned FOLDER INSIDE Cloned_certificates FOLDER.
    if single:
        command = "cat " + clon_path+ "cloned_certificate.*.pem > " + clon_path+ "cloned_certs.pem"
        std = os.system(command)       
        with open (clon_path + "cloned_certs.pem",'r') as f:
            cloned_pem_chain = f.read()

        with open (clon_path + "cloned_certificate.0.key") as f:
            private_key = f.read()


    else:
        with open (clon_path + "cloned_certificate.pem",'r') as f:
            cloned_pem_chain = f.read()

        with open (clon_path + "cloned_certificate.key") as f:
            private_key = f.read()"""
    
    return cloned_pem_chain, private_key




# STORE_CERT  
###------------------------------------------------------------------------------------------------------------------------------------
def store_cert(raw_certificates,id,directory_path):
    """Store cert function: 
        * Operation: stores the captured certificates in the Captured folder for Cerlog mode 
                     or in the aux folder for Verbose mode.

        * Function used by the following functions: cert_info.
        * Use the following functions: colors.
        * Use the following libraries: os, rmtree from shutil, ssl.

        * Input arguments:
            -raw_certificates: raw certificates captured. <pyshark.packet type> (der format).
            -id: ID from the packet o connection. <int type>
            -directory_path: directory where the certificate will be stored. <string type>
    """

    # PRELIMINARS.
    id_name = "ID_" + str(id) # Name of the corresponding ID folder.
    folder_path = directory_path + id_name # Path of the corresponding ID folder.

    try:
        os.mkdir(folder_path) # Generate folder in folder_path path.
    except FileExistsError: # Overwrite folder.
        sh.rmtree(folder_path)
        os.mkdir(folder_path)      


    # STORING THE CERTS.
    pem_chain = []
    chain_file = open(folder_path + "/ori_chain.pem",'w')
    n_certs = len(raw_certificates)
    for k in range(n_certs): # For any certificate string in packet...
        binary_cert = raw_certificates[k].binary_value # Getting the certificate binary value.
        cert_name = "/certificate" + str(k)+".crt"
        cert_path = folder_path + cert_name

        # Creating certificate0.crt, certificate1.crt, certificate2.crt ... in ID_id folder.
        f = open(cert_path,"wb")
        f.write(binary_cert)
        f.close()

        # Store ori_chain pem certificate .
        pem_cert = ssl.DER_cert_to_PEM_cert(binary_cert)
        chain_file.write(pem_cert)
        pem_chain.append(pem_cert)

    chain_file.close()
    return pem_chain



    
# CERT_INFO
###------------------------------------------------------------------------------------------------------------------------------------
def cert_info(raw_packet,mode):
    """Cert info function: 
        * Operation: Extract the common name, publik key length and 
          pem chain information to the certificate.

        * Use the following functions: store_cert, extract_cert.
        * Use the following libraries: -

        * Input arguments:
            -raw_packet: raw packet captured. <pyshark.packet type>.
            -mode: Operating mode. Verbose or Cerlog. <string type>.

        * Output arguments: 
            -cert_details: certificate details. <dict type>.
            -cert_details_to_print: certificate details prepared for print. <dict type>.
            -c_head: list with the headers to print a table with certificate details. <list type>. 
    """
    
    # PRELIMINARS.
    raw_certificates = raw_packet.tls.handshake_certificate.all_fields # All certificate strings captured in packet.
    id = raw_packet[raw_packet.transport_layer].dstport # ID (Client port).
    id_name = "ID_" + str(id) # Name of the corresponding ID folder in Captured certificates.
    if mode == '100000': # Verbose mode
        directory_path = tmp_captured_path + "verbose_captured_certs/" # Path for captured verbose captured certificates operations.
    elif mode == '010000': # Cerlog mode
        directory_path = tmp_captured_path + "cerlog_captured_certs/" # Path for captured cerlog captured certificates operations.

    ori_chain = store_cert(raw_certificates, id, directory_path)

    id_path = directory_path + id_name # Path of the corresponding ID folder in Captured certificate for aux_folder.

    c_name = []
    pk_size = []
    for k in range(len(raw_certificates)): # For any certificate string in packet...
        cert_name = "/certificate" + str(k)+".crt"
        cert_path = id_path + cert_name

        cert_data = (extract_cert(cert_path)) # Extract the c_name and publik key size.
        c_name.append(cert_data[0])
        pk_size.append(cert_data[1])
 
    cert_details_to_print = {"c_name": c_name, "public_key_length": pk_size}
    c_head = ["C_name", "Public key length (bits)"] 

    cert_details = {"c_name": c_name, "public_key_length": pk_size,"certificates":ori_chain}
    
    return cert_details,cert_details_to_print,c_head




#  CONNECTION CLASS
###------------------------------------------------------------------------------------------------------------------------------------
class Connection :
    """Connection class: 
        * Operation: Store data from each connection.

        * Use the following libraries: ssl.
    """
    def __init__(self):
        self.server_name = ''
        self.id = 0
        self.ip_client = ''
        self.ip_server = ''
        self.server_port = 0
        self.color = ''
        self.undercolor = ''
        self.control = []
        self.chosen_tls_version = ''
        self.chosen_cipher_suite = ''
        self.txt_file_name= ''
        self.pem_chain = []
        self.certificates = []
        self.cipher_code_error = ''

    def set_server_name(self,server_name):
        self.server_name = server_name

    def set_id(self,id):
        self.id = id

    def set_ip_client(self,ip_client):
        self.ip_client = ip_client
    
    def set_ip_server(self,ip_server):
        self.ip_server = ip_server
    
    def set_server_port(self,server_port):
        self.server_port = server_port

    def set_color(self,color):
        self.color = color

    def set_undercolor(self,undercolor):
        self.undercolor = undercolor

    def add_control(self,control):
        self.control.append(control)
    
    def set_chosen_tls_version(self,chosen_tls_version):
        self.chosen_tls_version = chosen_tls_version

    def set_chosen_cipher_suite(self,chosen_cipher_suite):
        self.chosen_cipher_suite = chosen_cipher_suite

    def set_txt_file_name(self,txt_file_name):
        self.txt_file_name= txt_file_name

    def set_pem_chain(self,pem_chain):
        self.pem_chain = pem_chain
        
    def set_cipher_code_error(self,code):
        self.cipher_code_error = code




# SHA256
###------------------------------------------------------------------------------------------------------------------------------------
def sha256(bytes_file):
    """Sha256 function: 
        * Operation: calculates the sha256 hash of a file.

        * Use the following libraries: hashlib.

        * Input arguments:
            -bytes_file: file to digest. <bytes type>.

        * Output arguments: 
            -sha256: digest of the file. <string type>.
    """
    hashObj = hashlib.sha256()
    hashObj.update(bytes_file)
    lastHash = hashObj.hexdigest().upper()
    sha256 = lastHash
    return sha256




# KILL_SONS 
#------------------------------------------------------------------------------------
def kill_sons(proc_pid):
    """kill_sons function:
        * Operation: Kill any child processes process with <proc_pid> pid. 
        * Function used by the following functions: -
        * Use the following functions: -
        * Libraries needed: psutil.
        
        * Input arguments:
            -proc_pid: process PID. <Int type>.
        
        * Output arguments: -
    """
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()

    
    
        
# DICTIONARY 
###------------------------------------------------------------------------------------------------------------------------------------
def dictionary():
    
    code = ['0xC030', '0xC02F', '0xCCA8', '0xC02B', '0xC02C', '0xC0AD', '0xC0AC', '0xCCA9', '0x1301', '0x1302', '0x1303', '0x1304', 
            '0x1305', '0x009F', '0x009E', '0xC09F', '0xC09E', '0xC024', '0xC023', '0xC028', '0xC027', '0x006B', '0x0067', '0x009D', 
            '0x009C', '0xC09D', '0xC09C', '0x003D', '0x003C', '0x0000', '0x0001', '0x0002', '0x0003', '0x0004', '0x0005', '0x0006', 
            '0x0007', '0x0008', '0x0009', '0x000A', '0x000B', '0x000C', '0x000D', '0x000E', '0x000F', '0x0010', '0x0011', '0x0012', 
            '0x0013', '0x0014', '0x0015', '0x0016', '0x0017', '0x0018', '0x0019', '0x001A', '0x001B', '0x001E', '0x001F', '0x0020', 
            '0x0021', '0x0022', '0x0023', '0x0024', '0x0025', '0x0026', '0x0027', '0x0028', '0x0029', '0x002A', '0x002B', '0x002C', 
            '0x002D', '0x002E', '0x002F', '0x0030', '0x0031', '0x0032', '0x0033', '0x0034', '0x0035', '0x0036', '0x0037', '0x0038', 
            '0x0039', '0x003A', '0x003B', '0x003E', '0x003F', '0x0040', '0x0041', '0x0042', '0x0043', '0x0044', '0x0045', '0x0046', 
            '0x0068', '0x0069', '0x006A', '0x006C', '0x006D', '0x0084', '0x0085', '0x0086', '0x0087', '0x0088', '0x0089', '0x008A', 
            '0x008B', '0x008C', '0x008D', '0x008E', '0x008F', '0x0090', '0x0091', '0x0092', '0x0093', '0x0094', '0x0095', '0x0096', 
            '0x0097', '0x0098', '0x0099', '0x009A', '0x009B', '0x00A0', '0x00A1', '0x00A2', '0x00A3', '0x00A4', '0x00A5', '0x00A6', 
            '0x00A7', '0x00A8', '0x00A9', '0x00AA', '0x00AB', '0x00AC', '0x00AD', '0x00AE', '0x00AF', '0x00B0', '0x00B1', '0x00B2', 
            '0x00B3', '0x00B4', '0x00B5', '0x00B6', '0x00B7', '0x00B8', '0x00B9', '0x00BA', '0x00BB', '0x00BC', '0x00BD', '0x00BE', 
            '0x00BF', '0x00C0', '0x00C1', '0x00C2', '0x00C3', '0x00C4', '0x00C5', '0x00C6', '0x00C7', '0x00FF', '0x5600', '0xC001', 
            '0xC002', '0xC003', '0xC004', '0xC005', '0xC006', '0xC007', '0xC008', '0xC009', '0xC00A', '0xC00B', '0xC00C', '0xC00D', 
            '0xC00E', '0xC00F', '0xC010', '0xC011', '0xC012', '0xC013', '0xC014', '0xC015', '0xC016', '0xC017', '0xC018', '0xC019', 
            '0xC01A', '0xC01B', '0xC01C', '0xC01D', '0xC01E', '0xC01F', '0xC020', '0xC021', '0xC022', '0xC025', '0xC026', '0xC029', 
            '0xC02A', '0xC02D', '0xC02E', '0xC031', '0xC032', '0xC033', '0xC034', '0xC035', '0xC036', '0xC037', '0xC038', '0xC039', 
            '0xC03A', '0xC03B', '0xC03C', '0xC03D', '0xC03E', '0xC03F', '0xC040', '0xC041', '0xC042', '0xC043', '0xC044', '0xC045', 
            '0xC046', '0xC047', '0xC048', '0xC049', '0xC04A', '0xC04B', '0xC04C', '0xC04D', '0xC04E', '0xC04F', '0xC050', '0xC051', 
            '0xC052', '0xC053', '0xC054', '0xC055', '0xC056', '0xC057', '0xC058', '0xC059', '0xC05A', '0xC05B', '0xC05C', '0xC05D', 
            '0xC05E', '0xC05F', '0xC060', '0xC061', '0xC062', '0xC063', '0xC064', '0xC065', '0xC066', '0xC067', '0xC068', '0xC069', 
            '0xC06A', '0xC06B', '0xC06C', '0xC06D', '0xC06E', '0xC06F', '0xC070', '0xC071', '0xC072', '0xC073', '0xC074', '0xC075', 
            '0xC076', '0xC077', '0xC078', '0xC079', '0xC07A', '0xC07B', '0xC07C', '0xC07D', '0xC07E', '0xC07F', '0xC080', '0xC081', 
            '0xC082', '0xC083', '0xC084', '0xC085', '0xC086', '0xC087', '0xC088', '0xC089', '0xC08A', '0xC08B', '0xC08C', '0xC08D', 
            '0xC08E', '0xC08F', '0xC090', '0xC091', '0xC092', '0xC093', '0xC094', '0xC095', '0xC096', '0xC097', '0xC098', '0xC099', 
            '0xC09A', '0xC09B', '0xC0A0', '0xC0A1', '0xC0A2', '0xC0A3', '0xC0A4', '0xC0A5', '0xC0A6', '0xC0A7', '0xC0A8', '0xC0A9', 
            '0xC0AA', '0xC0AB', '0xC0AE', '0xC0AF', '0xC0B0', '0xC0B1', '0xC0B2', '0xC0B3', '0xC0B4', '0xC0B5', '0xC100', '0xC101', 
            '0xC102', '0xC103', '0xC104', '0xC105', '0xC106', '0xCCAA', '0xCCAB', '0xCCAC', '0xCCAD', '0xCCAE', '0xD001', '0xD002', 
            '0xD003', '0xD005']
    
    category = ['R', 'R', 'R', 'R', 'R', 'R', 'R', 'R', 'R', 'R', 'R', 'R', 'R', 'L', 'L', 'L', 'L', 'L', 'L', 'L', 'L', 'L', 'L', 
                'L', 'L', 'L', 'L', 'L', 'L', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 'NR', 
                'NR', 'NR', 'NR']
    
    tls_cipher = ['TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 
                  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM', 
                  'TLS_ECDHE_ECDSA_WITH_AES_128_CCM', 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 
                  'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_CCM_SHA256', 'TLS_AES_128_CCM_8_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 
                  'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_CCM', 'TLS_DHE_RSA_WITH_AES_128_CCM', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', 
                  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 
                  'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'TLS_RSA_WITH_AES_128_GCM_SHA256', 
                  'TLS_RSA_WITH_AES_256_CCM', 'TLS_RSA_WITH_AES_128_CCM', 'TLS_RSA_WITH_AES_256_CBC_SHA256', 'TLS_RSA_WITH_AES_128_CBC_SHA256', 
                  'TLS_NULL_WITH_NULL_NULL', 'TLS_RSA_WITH_NULL_MD5', 'TLS_RSA_WITH_NULL_SHA', 'TLS_RSA_EXPORT_WITH_RC4_40_MD5', 'TLS_RSA_WITH_RC4_128_MD5', 
                  'TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5', 'TLS_RSA_WITH_IDEA_CBC_SHA', 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA', 
                  'TLS_RSA_WITH_DES_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA', 'TLS_DH_DSS_WITH_DES_CBC_SHA', 
                  'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA', 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA', 'TLS_DH_RSA_WITH_DES_CBC_SHA', 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA', 
                  'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA', 'TLS_DHE_DSS_WITH_DES_CBC_SHA', 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA', 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA', 
                  'TLS_DHE_RSA_WITH_DES_CBC_SHA', 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5', 'TLS_DH_anon_WITH_RC4_128_MD5', 
                  'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA', 'TLS_DH_anon_WITH_DES_CBC_SHA', 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA', 'TLS_KRB5_WITH_DES_CBC_SHA', 
                  'TLS_KRB5_WITH_3DES_EDE_CBC_SHA', 'TLS_KRB5_WITH_RC4_128_SHA', 'TLS_KRB5_WITH_IDEA_CBC_SHA', 'TLS_KRB5_WITH_DES_CBC_MD5', 
                  'TLS_KRB5_WITH_3DES_EDE_CBC_MD5', 'TLS_KRB5_WITH_RC4_128_MD5', 'TLS_KRB5_WITH_IDEA_CBC_MD5', 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA', 
                  'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA', 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA', 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5', 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5', 
                  'TLS_KRB5_EXPORT_WITH_RC4_40_MD5', 'TLS_PSK_WITH_NULL_SHA', 'TLS_DHE_PSK_WITH_NULL_SHA', 'TLS_RSA_PSK_WITH_NULL_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA', 
                  'TLS_DH_DSS_WITH_AES_128_CBC_SHA', 'TLS_DH_RSA_WITH_AES_128_CBC_SHA', 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 
                  'TLS_DH_anon_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_DH_DSS_WITH_AES_256_CBC_SHA', 'TLS_DH_RSA_WITH_AES_256_CBC_SHA', 
                  'TLS_DHE_DSS_WITH_AES_256_CBC_SHA', 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_DH_anon_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_NULL_SHA256', 
                  'TLS_DH_DSS_WITH_AES_128_CBC_SHA256', 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256', 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256', 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA', 
                  'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA', 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA', 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA', 
                  'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA', 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA', 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256', 
                  'TLS_DH_RSA_WITH_AES_256_CBC_SHA256', 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256', 'TLS_DH_anon_WITH_AES_128_CBC_SHA256', 
                  'TLS_DH_anon_WITH_AES_256_CBC_SHA256', 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA', 
                  'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA', 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA', 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA', 
                  'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA', 'TLS_PSK_WITH_RC4_128_SHA', 'TLS_PSK_WITH_3DES_EDE_CBC_SHA', 'TLS_PSK_WITH_AES_128_CBC_SHA', 
                  'TLS_PSK_WITH_AES_256_CBC_SHA', 'TLS_DHE_PSK_WITH_RC4_128_SHA', 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA', 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA', 
                  'TLS_DHE_PSK_WITH_AES_256_CBC_SHA', 'TLS_RSA_PSK_WITH_RC4_128_SHA', 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA', 
                  'TLS_RSA_PSK_WITH_AES_256_CBC_SHA', 'TLS_RSA_WITH_SEED_CBC_SHA', 'TLS_DH_DSS_WITH_SEED_CBC_SHA', 'TLS_DH_RSA_WITH_SEED_CBC_SHA', 
                  'TLS_DHE_DSS_WITH_SEED_CBC_SHA', 'TLS_DHE_RSA_WITH_SEED_CBC_SHA', 'TLS_DH_anon_WITH_SEED_CBC_SHA', 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256', 
                  'TLS_DH_RSA_WITH_AES_256_GCM_SHA384', 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256', 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384', 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256', 
                  'TLS_DH_DSS_WITH_AES_256_GCM_SHA384', 'TLS_DH_anon_WITH_AES_128_GCM_SHA256', 'TLS_DH_anon_WITH_AES_256_GCM_SHA384', 'TLS_PSK_WITH_AES_128_GCM_SHA256', 
                  'TLS_PSK_WITH_AES_256_GCM_SHA384', 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256', 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384', 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256', 
                  'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384', 'TLS_PSK_WITH_AES_128_CBC_SHA256', 'TLS_PSK_WITH_AES_256_CBC_SHA384', 'TLS_PSK_WITH_NULL_SHA256', 
                  'TLS_PSK_WITH_NULL_SHA384', 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256', 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384', 'TLS_DHE_PSK_WITH_NULL_SHA256', 
                  'TLS_DHE_PSK_WITH_NULL_SHA384', 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256', 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384', 'TLS_RSA_PSK_WITH_NULL_SHA256', 
                  'TLS_RSA_PSK_WITH_NULL_SHA384', 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256', 
                  'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256', 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256', 
                  'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256', 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256', 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256', 
                  'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256', 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256', 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256', 
                  'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256', 'TLS_SM4_GCM_SM3', 'TLS_SM4_CCM_SM3', 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV', 'TLS_FALLBACK_SCSV', 
                  'TLS_ECDH_ECDSA_WITH_NULL_SHA', 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA', 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA', 
                  'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_NULL_SHA', 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA', 
                  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDH_RSA_WITH_NULL_SHA', 'TLS_ECDH_RSA_WITH_RC4_128_SHA', 
                  'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_NULL_SHA', 
                  'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 
                  'TLS_ECDH_anon_WITH_NULL_SHA', 'TLS_ECDH_anon_WITH_RC4_128_SHA', 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA', 
                  'TLS_ECDH_anon_WITH_AES_256_CBC_SHA', 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA', 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA', 
                  'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA', 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA', 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA', 
                  'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA', 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA', 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA', 
                  'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA', 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384', 
                  'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384', 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256', 
                  'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384', 
                  'TLS_ECDHE_PSK_WITH_RC4_128_SHA', 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA', 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA', 
                  'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384', 'TLS_ECDHE_PSK_WITH_NULL_SHA', 'TLS_ECDHE_PSK_WITH_NULL_SHA256', 
                  'TLS_ECDHE_PSK_WITH_NULL_SHA384', 'TLS_RSA_WITH_ARIA_128_CBC_SHA256', 'TLS_RSA_WITH_ARIA_256_CBC_SHA384', 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256', 
                  'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384', 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256', 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384', 
                  'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256', 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384', 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256', 
                  'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384', 'TLS_DH_anon_WITH_ARIA_128_CBC_SHA256', 'TLS_DH_anon_WITH_ARIA_256_CBC_SHA384', 
                  'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256', 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384', 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256', 
                  'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384', 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384', 
                  'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256', 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384', 'TLS_RSA_WITH_ARIA_128_GCM_SHA256', 
                  'TLS_RSA_WITH_ARIA_256_GCM_SHA384', 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384', 
                  'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256', 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384', 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256', 
                  'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384', 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256', 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384', 
                  'TLS_DH_anon_WITH_ARIA_128_GCM_SHA256', 'TLS_DH_anon_WITH_ARIA_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256', 
                  'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384', 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256', 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384', 
                  'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384', 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256', 
                  'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384', 'TLS_PSK_WITH_ARIA_128_CBC_SHA256', 'TLS_PSK_WITH_ARIA_256_CBC_SHA384', 
                  'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256', 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384', 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256', 
                  'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384', 'TLS_PSK_WITH_ARIA_128_GCM_SHA256', 'TLS_PSK_WITH_ARIA_256_GCM_SHA384', 
                  'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256', 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384', 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256', 
                  'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384', 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256', 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384', 
                  'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256', 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384', 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256', 
                  'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384', 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384', 
                  'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384', 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256', 
                  'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384', 
                  'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256', 
                  'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384', 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256', 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384', 
                  'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256', 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384', 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256', 
                  'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384', 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256', 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384', 
                  'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256', 
                  'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256', 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384', 
                  'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256', 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384', 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256', 
                  'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384', 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256', 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384', 
                  'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256', 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384', 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256', 
                  'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384', 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256', 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384', 
                  'TLS_RSA_WITH_AES_128_CCM_8', 'TLS_RSA_WITH_AES_256_CCM_8', 'TLS_DHE_RSA_WITH_AES_128_CCM_8', 'TLS_DHE_RSA_WITH_AES_256_CCM_8', 
                  'TLS_PSK_WITH_AES_128_CCM', 'TLS_PSK_WITH_AES_256_CCM', 'TLS_DHE_PSK_WITH_AES_128_CCM', 'TLS_DHE_PSK_WITH_AES_256_CCM', 'TLS_PSK_WITH_AES_128_CCM_8', 
                  'TLS_PSK_WITH_AES_256_CCM_8', 'TLS_PSK_DHE_WITH_AES_128_CCM_8', 'TLS_PSK_DHE_WITH_AES_256_CCM_8', 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8', 
                  'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8', 'TLS_ECCPWD_WITH_AES_128_GCM_SHA256', 'TLS_ECCPWD_WITH_AES_256_GCM_SHA384', 'TLS_ECCPWD_WITH_AES_128_CCM_SHA256', 
                  'TLS_ECCPWD_WITH_AES_256_CCM_SHA384', 'TLS_SHA256_SHA256', 'TLS_SHA384_SHA384', 'TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC', 
                  'TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC', 'TLS_GOSTR341112_256_WITH_28147_CNT_IMIT', 'TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L', 
                  'TLS_GOSTR341112_256_WITH_MAGMA_MGM_L', 'TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S', 'TLS_GOSTR341112_256_WITH_MAGMA_MGM_S', 
                  'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256', 
                  'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256', 'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256', 
                  'TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256', 'TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256']
    
    ssl_cipher = ['ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-CHACHA20-POLY1305', 'ECDHE-ECDSA-AES128-GCM-SHA256', 
                  'ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES256-CCM', 'ECDHE-ECDSA-AES128-CCM', 'ECDHE-ECDSA-CHACHA20-POLY1305', 'TLS_AES_128_GCM_SHA256', 
                  'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'TLS_AES_128_CCM_SHA256', 'TLS_AES_128_CCM_8_SHA256', 'DHE-RSA-AES256-GCM-SHA384', 
                  'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES256-CCM', 'DHE-RSA-AES128-CCM', 'ECDHE-ECDSA-AES256-SHA384', 'ECDHE-ECDSA-AES128-SHA256', 
                  'ECDHE-RSA-AES256-SHA384', 'ECDHE-RSA-AES128-SHA256', 'DHE-RSA-AES256-SHA256', 'DHE-RSA-AES128-SHA256', 'AES256-GCM-SHA384', 'AES128-GCM-SHA256', 
                  'AES256-CCM', 'none', 'AES256-SHA256', 'AES128-SHA256', 'none', 'none', 'none', 'EXP-RC4-MD5', 'RC4-MD5', 'RC4-SHA', 'EXP-RC2-CBC-MD5', 
                  'IDEA-CBC-SHA', 'EXP-DES-CBC-SHA', 'DES-CBC-SHA', 'DES-CBC3-SHA', 'EXP-DH-DSS-DES-CBC-SHA', 'DH-DSS-DES-CBC-SHA', 'DH-DSS-DES-CBC3-SHA', 
                  'EXP-DH-RSA-DES-CBC-SHA', 'DH-RSA-DES-CBC-SHA', 'DH-RSA-DES-CBC3-SHA', 'EXP-EDH-DSS-DES-CBC-SHA', 'EDH-DSS-DES-CBC-SHA', 'EDH-DSS-DES-CBC3-SHA', 
                  'EXP-EDH-RSA-DES-CBC-SHA', 'EDH-RSA-DES-CBC-SHA', 'EDH-RSA-DES-CBC3-SHA', 'EXP-ADH-RC4-MD5', 'ADH-RC4-MD5', 'EXP-ADH-DES-CBC-SHA', 'ADH-DES-CBC-SHA', 
                  'ADH-DES-CBC3-SHA', 'KRB5-DES-CBC-SHA', 'KRB5-DES-CBC3-SHA', 'KRB5-RC4-SHA', 'KRB5-IDEA-CBC-SHA', 'KRB5-DES-CBC-MD5', 'KRB5-DES-CBC3-MD5', 
                  'KRB5-RC4-MD5', 'KRB5-IDEA-CBC-MD5', 'EXP-KRB5-DES-CBC-SHA', 'EXP-KRB5-RC2-CBC-SHA', 'EXP-KRB5-RC4-SHA', 'EXP-KRB5-DES-CBC-MD5', 'EXP-KRB5-RC2-CBC-MD5', 
                  'EXP-KRB5-RC4-MD5', 'PSK-NULL-SHA', 'DHE-PSK-NULL-SHA', 'RSA-PSK-NULL-SHA', 'AES128-SHA', 'DH-DSS-AES128-SHA', 'DH-RSA-AES128-SHA', 'DHE-DSS-AES128-SHA', 
                  'DHE-RSA-AES128-SHA', 'ADH-AES128-SHA', 'AES256-SHA', 'DH-DSS-AES256-SHA', 'DH-RSA-AES256-SHA', 'DHE-DSS-AES256-SHA', 'DHE-RSA-AES256-SHA', 
                  'ADH-AES256-SHA', 'NULL-SHA256', 'DH-DSS-AES128-SHA256', 'DH-RSA-AES128-SHA256', 'DHE-DSS-AES128-SHA256', 'CAMELLIA128-SHA', 'DH-DSS-CAMELLIA128-SHA', 
                  'DH-RSA-CAMELLIA128-SHA', 'DHE-DSS-CAMELLIA128-SHA', 'DHE-RSA-CAMELLIA128-SHA', 'ADH-CAMELLIA128-SHA', 'DH-DSS-AES256-SHA256', 'DH-RSA-AES256-SHA256', 
                  'DHE-DSS-AES256-SHA256', 'ADH-AES128-SHA256', 'ADH-AES256-SHA256', 'CAMELLIA256-SHA', 'DH-DSS-CAMELLIA256-SHA', 'DH-RSA-CAMELLIA256-SHA', 
                  'DHE-DSS-CAMELLIA256-SHA', 'DHE-RSA-CAMELLIA256-SHA', 'ADH-CAMELLIA256-SHA', 'PSK-RC4-SHA', 'PSK-3DES-EDE-CBC-SHA', 'PSK-AES128-CBC-SHA', 
                  'PSK-AES256-CBC-SHA', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'SEED-SHA', 'DH-DSS-SEED-SHA', 'DH-RSA-SEED-SHA', 
                  'DHE-DSS-SEED-SHA', 'DHE-RSA-SEED-SHA', 'ADH-SEED-SHA', 'DH-RSA-AES128-GCM-SHA256', 'DH-RSA-AES256-GCM-SHA384', 'DHE-DSS-AES128-GCM-SHA256', 
                  'DHE-DSS-AES256-GCM-SHA384', 'DH-DSS-AES128-GCM-SHA256', 'DH-DSS-AES256-GCM-SHA384', 'ADH-AES128-GCM-SHA256', 'ADH-AES256-GCM-SHA384', 'none', 
                  'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 
                  'CAMELLIA128-SHA256', 'DH-DSS-CAMELLIA128-SHA256', 'DH-RSA-CAMELLIA128-SHA256', 'DHE-DSS-CAMELLIA128-SHA256', 'DHE-RSA-CAMELLIA128-SHA256', 
                  'ADH-CAMELLIA128-SHA256', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'TLS_FALLBACK_SCSV', 'ECDH-ECDSA-NULL-SHA', 
                  'ECDH-ECDSA-RC4-SHA', 'ECDH-ECDSA-DES-CBC3-SHA', 'ECDH-ECDSA-AES128-SHA', 'ECDH-ECDSA-AES256-SHA', 'ECDHE-ECDSA-NULL-SHA', 'ECDHE-ECDSA-RC4-SHA', 
                  'ECDHE-ECDSA-DES-CBC3-SHA', 'ECDHE-ECDSA-AES128-SHA', 'ECDHE-ECDSA-AES256-SHA', 'ECDH-RSA-NULL-SHA', 'ECDH-RSA-RC4-SHA', 'ECDH-RSA-DES-CBC3-SHA', 
                  'ECDH-RSA-AES128-SHA', 'ECDH-RSA-AES256-SHA', 'ECDHE-RSA-NULL-SHA', 'ECDHE-RSA-RC4-SHA', 'ECDHE-RSA-DES-CBC3-SHA', 'ECDHE-RSA-AES128-SHA', 
                  'ECDHE-RSA-AES256-SHA', 'AECDH-NULL-SHA', 'AECDH-RC4-SHA', 'AECDH-DES-CBC3-SHA', 'AECDH-AES128-SHA', 'AECDH-AES256-SHA', 'SRP-3DES-EDE-CBC-SHA', 
                  'SRP-RSA-3DES-EDE-CBC-SHA', 'SRP-DSS-3DES-EDE-CBC-SHA', 'SRP-AES-128-CBC-SHA', 'SRP-RSA-AES-128-CBC-SHA', 'SRP-DSS-AES-128-CBC-SHA', 
                  'SRP-AES-256-CBC-SHA', 'SRP-RSA-AES-256-CBC-SHA', 'SRP-DSS-AES-256-CBC-SHA', 'ECDH-ECDSA-AES128-SHA256', 'ECDH-ECDSA-AES256-SHA384', 
                  'ECDH-RSA-AES128-SHA256', 'ECDH-RSA-AES256-SHA384', 'ECDH-ECDSA-AES128-GCM-SHA256', 'ECDH-ECDSA-AES256-GCM-SHA384', 'ECDH-RSA-AES128-GCM-SHA256', 
                  'ECDH-RSA-AES256-GCM-SHA384', 'ECDHE-PSK-RC4-SHA', 'ECDHE-PSK-3DES-EDE-CBC-SHA', 'ECDHE-PSK-AES128-CBC-SHA', 'ECDHE-PSK-AES256-CBC-SHA', 
                  'ECDHE-PSK-AES128-CBC-SHA256', 'ECDHE-PSK-AES256-CBC-SHA384', 'ECDHE-PSK-NULL-SHA', 'ECDHE-PSK-NULL-SHA256', 'ECDHE-PSK-NULL-SHA384', 'none', 'none', 
                  'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 
                  'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 
                  'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'ECDHE-ECDSA-CAMELLIA128-SHA256', 
                  'ECDHE-ECDSA-CAMELLIA256-SHA38', 'ECDH-ECDSA-CAMELLIA128-SHA256', 'ECDH-ECDSA-CAMELLIA256-SHA384', 'ECDHE-RSA-CAMELLIA128-SHA256', 
                  'ECDHE-RSA-CAMELLIA256-SHA384', 'ECDH-RSA-CAMELLIA128-SHA256', 'ECDH-RSA-CAMELLIA256-SHA384', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 
                  'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 'none', 
                  'PSK-CAMELLIA128-SHA256', 'PSK-CAMELLIA256-SHA384', 'DHE-PSK-CAMELLIA128-SHA256', 'DHE-PSK-CAMELLIA256-SHA384', 'RSA-PSK-CAMELLIA128-SHA256', 
                  'RSA-PSK-CAMELLIA256-SHA384', 'ECDHE-PSK-CAMELLIA128-SHA256', 'ECDHE-PSK-CAMELLIA256-SHA384', 'AES128-CCM8', 'AES256-CCM8', 'DHE-RSA-AES128-CCM8', 
                  'DHE-RSA-AES256-CCM8', 'PSK-AES128-CCM', 'PSK-AES256-CCM', 'DHE-PSK-AES128-CCM', 'DHE-PSK-AES256-CCM', 'PSK-AES128-CCM8', 'PSK-AES256-CCM8', 
                  'DHE-PSK-AES128-CCM8', 'DHE-PSK-AES256-CCM8', 'ECDHE-ECDSA-AES128-CCM8', 'ECDHE-ECDSA-AES256-CCM8', 'none', 'none', 'none', 'none', 'none', 'none', 
                  'none', 'none', 'none', 'none', 'none', 'none', 'none', 'DHE-RSA-CHACHA20-POLY1305', 'PSK-CHACHA20-POLY1305', 'ECDHE-PSK-CHACHA20-POLY1305', 
                  'DHE-PSK-CHACHA20-POLY1305', 'RSA-PSK-CHACHA20-POLY1305', 'none', 'none', 'none', 'none']
    
    dic = {"codes":code,"categories":category,"tls_ciphers":tls_cipher,"ssl_ciphers":ssl_cipher}
    
    return dic




"""# DICTIONARY INFO
###------------------------------------------------------------------------------------------------------------------------------------
          ([['0xC030','R','TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384','ECDHE-RSA-AES256-GCM-SHA384','TLS1.2'],
            ['0xC02F','R','TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256','ECDHE-RSA-AES128-GCM-SHA256','TLS1.2'],
            ['0xCCA8','R','TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256','ECDHE-RSA-CHACHA20-POLY1305','TLS1.2'],
            ['0xC02B','R','TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256','ECDHE-ECDSA-AES128-GCM-SHA256','TLS1.2'],
            ['0xC02C','R','TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384','ECDHE-ECDSA-AES256-GCM-SHA384','TLS1.2'],
            ['0xC0AD','R','TLS_ECDHE_ECDSA_WITH_AES_256_CCM','ECDHE-ECDSA-AES256-CCM','TLS1.2'],
            ['0xC0AC','R','TLS_ECDHE_ECDSA_WITH_AES_128_CCM','ECDHE-ECDSA-AES128-CCM','TLS1.2'],
            ['0xCCA9','R','TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256','ECDHE-ECDSA-CHACHA20-POLY1305','TLS1.2'],
            ['0x1301','R','TLS_AES_128_GCM_SHA256','TLS_AES_128_GCM_SHA256','TLS1.3'],
            ['0x1302','R','TLS_AES_256_GCM_SHA384','TLS_AES_256_GCM_SHA384','TLS1.3'],
            ['0x1303','R','TLS_CHACHA20_POLY1305_SHA256','TLS_CHACHA20_POLY1305_SHA256','TLS1.3'],
            ['0x1304','R','TLS_AES_128_CCM_SHA256','TLS_AES_128_CCM_SHA256','TLS1.3'],
            ['0x1305','R','TLS_AES_128_CCM_8_SHA256','TLS_AES_128_CCM_8_SHA256','TLS1.3'],
            ['0x009F','L','TLS_DHE_RSA_WITH_AES_256_GCM_SHA384','DHE-RSA-AES256-GCM-SHA384','TLS1.2'],
            ['0x009E','L','TLS_DHE_RSA_WITH_AES_128_GCM_SHA256','DHE-RSA-AES128-GCM-SHA256','TLS1.2'],
            ['0xC09F','L','TLS_DHE_RSA_WITH_AES_256_CCM','DHE-RSA-AES256-CCM','TLS1.2'],
            ['0xC09E','L','TLS_DHE_RSA_WITH_AES_128_CCM','DHE-RSA-AES128-CCM','TLS1.2'],
            ['0xC024','L','TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384','ECDHE-ECDSA-AES256-SHA384','TLS1.2'],
            ['0xC023','L','TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256','ECDHE-ECDSA-AES128-SHA256','TLS1.2'],
            ['0xC028','L','TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384','ECDHE-RSA-AES256-SHA384','TLS1.2'],
            ['0xC027','L','TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256','ECDHE-RSA-AES128-SHA256','TLS1.2'],
            ['0x006B','L','TLS_DHE_RSA_WITH_AES_256_CBC_SHA256','DHE-RSA-AES256-SHA256','TLS1.2'],
            ['0x0067','L','TLS_DHE_RSA_WITH_AES_128_CBC_SHA256','DHE-RSA-AES128-SHA256','TLS1.2'],
            ['0x009D','L','TLS_RSA_WITH_AES_256_GCM_SHA384','AES256-GCM-SHA384','TLS1.2'],
            ['0x009C','L','TLS_RSA_WITH_AES_128_GCM_SHA256','AES128-GCM-SHA256','TLS1.2'],
            ['0xC09D','L','TLS_RSA_WITH_AES_256_CCM','AES256-CCM','TLS1.2'],
            ['0xC09C','L','TLS_RSA_WITH_AES_128_CCM','none','TLS1.2'],
            ['0x003D','L','TLS_RSA_WITH_AES_256_CBC_SHA256','AES256-SHA256','TLS1.2'],
            ['0x003C','L','TLS_RSA_WITH_AES_128_CBC_SHA256','AES128-SHA256','TLS1.2'],
            ['0x0000','NR','TLS_NULL_WITH_NULL_NULL','none','TLS1.2'],
            ['0x0001','NR','TLS_RSA_WITH_NULL_MD5','none','TLS1.2'],
            ['0x0002','NR','TLS_RSA_WITH_NULL_SHA','none','TLS1.2'],
            ['0x0003','NR','TLS_RSA_EXPORT_WITH_RC4_40_MD5','EXP-RC4-MD5','TLS1.2'],
            ['0x0004','NR','TLS_RSA_WITH_RC4_128_MD5','RC4-MD5','TLS1.2'],
            ['0x0005','NR','TLS_RSA_WITH_RC4_128_SHA','RC4-SHA','TLS1.2'],
            ['0x0006','NR','TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5','EXP-RC2-CBC-MD5','TLS1.2'],
            ['0x0007','NR','TLS_RSA_WITH_IDEA_CBC_SHA','IDEA-CBC-SHA','TLS1.2'],
            ['0x0008','NR','TLS_RSA_EXPORT_WITH_DES40_CBC_SHA','EXP-DES-CBC-SHA','TLS1.2'],
            ['0x0009','NR','TLS_RSA_WITH_DES_CBC_SHA','DES-CBC-SHA','TLS1.2'],
            ['0x000A','NR','TLS_RSA_WITH_3DES_EDE_CBC_SHA','DES-CBC3-SHA','TLS1.2'],
            ['0x000B','NR','TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA','EXP-DH-DSS-DES-CBC-SHA','TLS1.2'],
            ['0x000C','NR','TLS_DH_DSS_WITH_DES_CBC_SHA','DH-DSS-DES-CBC-SHA','TLS1.2'],
            ['0x000D','NR','TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA','DH-DSS-DES-CBC3-SHA','TLS1.2'],
            ['0x000E','NR','TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA','EXP-DH-RSA-DES-CBC-SHA','TLS1.2'],
            ['0x000F','NR','TLS_DH_RSA_WITH_DES_CBC_SHA','DH-RSA-DES-CBC-SHA','TLS1.2'],
            ['0x0010','NR','TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA','DH-RSA-DES-CBC3-SHA','TLS1.2'],
            ['0x0011','NR','TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA','EXP-EDH-DSS-DES-CBC-SHA','TLS1.2'],
            ['0x0012','NR','TLS_DHE_DSS_WITH_DES_CBC_SHA','EDH-DSS-DES-CBC-SHA','TLS1.2'],
            ['0x0013','NR','TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA','EDH-DSS-DES-CBC3-SHA','TLS1.2'],
            ['0x0014','NR','TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA','EXP-EDH-RSA-DES-CBC-SHA','TLS1.2'],
            ['0x0015','NR','TLS_DHE_RSA_WITH_DES_CBC_SHA','EDH-RSA-DES-CBC-SHA','TLS1.2'],
            ['0x0016','NR','TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA','EDH-RSA-DES-CBC3-SHA','TLS1.2'],
            ['0x0017','NR','TLS_DH_anon_EXPORT_WITH_RC4_40_MD5','EXP-ADH-RC4-MD5','TLS1.2'],
            ['0x0018','NR','TLS_DH_anon_WITH_RC4_128_MD5','ADH-RC4-MD5','TLS1.2'],
            ['0x0019','NR','TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA','EXP-ADH-DES-CBC-SHA','TLS1.2'],
            ['0x001A','NR','TLS_DH_anon_WITH_DES_CBC_SHA','ADH-DES-CBC-SHA','TLS1.2'],
            ['0x001B','NR','TLS_DH_anon_WITH_3DES_EDE_CBC_SHA','ADH-DES-CBC3-SHA','TLS1.2'],
            ['0x001E','NR','TLS_KRB5_WITH_DES_CBC_SHA','KRB5-DES-CBC-SHA','TLS1.2'],
            ['0x001F','NR','TLS_KRB5_WITH_3DES_EDE_CBC_SHA','KRB5-DES-CBC3-SHA','TLS1.2'],
            ['0x0020','NR','TLS_KRB5_WITH_RC4_128_SHA','KRB5-RC4-SHA','TLS1.2'],
            ['0x0021','NR','TLS_KRB5_WITH_IDEA_CBC_SHA','KRB5-IDEA-CBC-SHA','TLS1.2'],
            ['0x0022','NR','TLS_KRB5_WITH_DES_CBC_MD5','KRB5-DES-CBC-MD5','TLS1.2'],
            ['0x0023','NR','TLS_KRB5_WITH_3DES_EDE_CBC_MD5','KRB5-DES-CBC3-MD5','TLS1.2'],
            ['0x0024','NR','TLS_KRB5_WITH_RC4_128_MD5','KRB5-RC4-MD5','TLS1.2'],
            ['0x0025','NR','TLS_KRB5_WITH_IDEA_CBC_MD5','KRB5-IDEA-CBC-MD5','TLS1.2'],
            ['0x0026','NR','TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA','EXP-KRB5-DES-CBC-SHA','TLS1.2'],
            ['0x0027','NR','TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA','EXP-KRB5-RC2-CBC-SHA','TLS1.2'],
            ['0x0028','NR','TLS_KRB5_EXPORT_WITH_RC4_40_SHA','EXP-KRB5-RC4-SHA','TLS1.2'],
            ['0x0029','NR','TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5','EXP-KRB5-DES-CBC-MD5','TLS1.2'],
            ['0x002A','NR','TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5','EXP-KRB5-RC2-CBC-MD5','TLS1.2'],
            ['0x002B','NR','TLS_KRB5_EXPORT_WITH_RC4_40_MD5','EXP-KRB5-RC4-MD5','TLS1.2'],
            ['0x002C','NR','TLS_PSK_WITH_NULL_SHA','PSK-NULL-SHA','TLS1.2'],
            ['0x002D','NR','TLS_DHE_PSK_WITH_NULL_SHA','DHE-PSK-NULL-SHA','TLS1.2'],
            ['0x002E','NR','TLS_RSA_PSK_WITH_NULL_SHA','RSA-PSK-NULL-SHA','TLS1.2'],
            ['0x002F','NR','TLS_RSA_WITH_AES_128_CBC_SHA','AES128-SHA','TLS1.2'],
            ['0x0030','NR','TLS_DH_DSS_WITH_AES_128_CBC_SHA','DH-DSS-AES128-SHA','TLS1.2'],
            ['0x0031','NR','TLS_DH_RSA_WITH_AES_128_CBC_SHA','DH-RSA-AES128-SHA','TLS1.2'],
            ['0x0032','NR','TLS_DHE_DSS_WITH_AES_128_CBC_SHA','DHE-DSS-AES128-SHA','TLS1.2'],
            ['0x0033','NR','TLS_DHE_RSA_WITH_AES_128_CBC_SHA','DHE-RSA-AES128-SHA','TLS1.2'],
            ['0x0034','NR','TLS_DH_anon_WITH_AES_128_CBC_SHA','ADH-AES128-SHA','TLS1.2'],
            ['0x0035','NR','TLS_RSA_WITH_AES_256_CBC_SHA','AES256-SHA','TLS1.2'],
            ['0x0036','NR','TLS_DH_DSS_WITH_AES_256_CBC_SHA','DH-DSS-AES256-SHA','TLS1.2'],
            ['0x0037','NR','TLS_DH_RSA_WITH_AES_256_CBC_SHA','DH-RSA-AES256-SHA','TLS1.2'],
            ['0x0038','NR','TLS_DHE_DSS_WITH_AES_256_CBC_SHA','DHE-DSS-AES256-SHA','TLS1.2'],
            ['0x0039','NR','TLS_DHE_RSA_WITH_AES_256_CBC_SHA','DHE-RSA-AES256-SHA','TLS1.2'],
            ['0x003A','NR','TLS_DH_anon_WITH_AES_256_CBC_SHA','ADH-AES256-SHA','TLS1.2'],
            ['0x003B','NR','TLS_RSA_WITH_NULL_SHA256','NULL-SHA256','TLS1.2'],
            ['0x003E','NR','TLS_DH_DSS_WITH_AES_128_CBC_SHA256','DH-DSS-AES128-SHA256','TLS1.2'],
            ['0x003F','NR','TLS_DH_RSA_WITH_AES_128_CBC_SHA256','DH-RSA-AES128-SHA256','TLS1.2'],
            ['0x0040','NR','TLS_DHE_DSS_WITH_AES_128_CBC_SHA256','DHE-DSS-AES128-SHA256','TLS1.2'],
            ['0x0041','NR','TLS_RSA_WITH_CAMELLIA_128_CBC_SHA','CAMELLIA128-SHA','TLS1.2'],
            ['0x0042','NR','TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA','DH-DSS-CAMELLIA128-SHA','TLS1.2'],
            ['0x0043','NR','TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA','DH-RSA-CAMELLIA128-SHA','TLS1.2'],
            ['0x0044','NR','TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA','DHE-DSS-CAMELLIA128-SHA','TLS1.2'],
            ['0x0045','NR','TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA','DHE-RSA-CAMELLIA128-SHA','TLS1.2'],
            ['0x0046','NR','TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA','ADH-CAMELLIA128-SHA','TLS1.2'],
            ['0x0068','NR','TLS_DH_DSS_WITH_AES_256_CBC_SHA256','DH-DSS-AES256-SHA256','TLS1.2'],
            ['0x0069','NR','TLS_DH_RSA_WITH_AES_256_CBC_SHA256','DH-RSA-AES256-SHA256','TLS1.2'],
            ['0x006A','NR','TLS_DHE_DSS_WITH_AES_256_CBC_SHA256','DHE-DSS-AES256-SHA256','TLS1.2'],
            ['0x006C','NR','TLS_DH_anon_WITH_AES_128_CBC_SHA256','ADH-AES128-SHA256','TLS1.2'],
            ['0x006D','NR','TLS_DH_anon_WITH_AES_256_CBC_SHA256','ADH-AES256-SHA256','TLS1.2'],
            ['0x0084','NR','TLS_RSA_WITH_CAMELLIA_256_CBC_SHA','CAMELLIA256-SHA','TLS1.2'],
            ['0x0085','NR','TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA','DH-DSS-CAMELLIA256-SHA','TLS1.2'],
            ['0x0086','NR','TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA','DH-RSA-CAMELLIA256-SHA','TLS1.2'],
            ['0x0087','NR','TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA','DHE-DSS-CAMELLIA256-SHA','TLS1.2'],
            ['0x0088','NR','TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA','DHE-RSA-CAMELLIA256-SHA','TLS1.2'],
            ['0x0089','NR','TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA','ADH-CAMELLIA256-SHA','TLS1.2'],
            ['0x008A','NR','TLS_PSK_WITH_RC4_128_SHA','PSK-RC4-SHA','TLS1.2'],
            ['0x008B','NR','TLS_PSK_WITH_3DES_EDE_CBC_SHA','PSK-3DES-EDE-CBC-SHA','TLS1.2'],
            ['0x008C','NR','TLS_PSK_WITH_AES_128_CBC_SHA','PSK-AES128-CBC-SHA','TLS1.2'],
            ['0x008D','NR','TLS_PSK_WITH_AES_256_CBC_SHA','PSK-AES256-CBC-SHA','TLS1.2'],
            ['0x008E','NR','TLS_DHE_PSK_WITH_RC4_128_SHA','none','TLS1.2'],
            ['0x008F','NR','TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA','none','TLS1.2'],
            ['0x0090','NR','TLS_DHE_PSK_WITH_AES_128_CBC_SHA','none','TLS1.2'],
            ['0x0091','NR','TLS_DHE_PSK_WITH_AES_256_CBC_SHA','none','TLS1.2'],
            ['0x0092','NR','TLS_RSA_PSK_WITH_RC4_128_SHA','none','TLS1.2'],
            ['0x0093','NR','TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA','none','TLS1.2'],
            ['0x0094','NR','TLS_RSA_PSK_WITH_AES_128_CBC_SHA','none','TLS1.2'],
            ['0x0095','NR','TLS_RSA_PSK_WITH_AES_256_CBC_SHA','none','TLS1.2'],
            ['0x0096','NR','TLS_RSA_WITH_SEED_CBC_SHA','SEED-SHA','TLS1.2'],
            ['0x0097','NR','TLS_DH_DSS_WITH_SEED_CBC_SHA','DH-DSS-SEED-SHA','TLS1.2'],
            ['0x0098','NR','TLS_DH_RSA_WITH_SEED_CBC_SHA','DH-RSA-SEED-SHA','TLS1.2'],
            ['0x0099','NR','TLS_DHE_DSS_WITH_SEED_CBC_SHA','DHE-DSS-SEED-SHA','TLS1.2'],
            ['0x009A','NR','TLS_DHE_RSA_WITH_SEED_CBC_SHA','DHE-RSA-SEED-SHA','TLS1.2'],
            ['0x009B','NR','TLS_DH_anon_WITH_SEED_CBC_SHA','ADH-SEED-SHA','TLS1.2'],
            ['0x00A0','NR','TLS_DH_RSA_WITH_AES_128_GCM_SHA256','DH-RSA-AES128-GCM-SHA256','TLS1.2'],
            ['0x00A1','NR','TLS_DH_RSA_WITH_AES_256_GCM_SHA384','DH-RSA-AES256-GCM-SHA384','TLS1.2'],
            ['0x00A2','NR','TLS_DHE_DSS_WITH_AES_128_GCM_SHA256','DHE-DSS-AES128-GCM-SHA256','TLS1.2'],
            ['0x00A3','NR','TLS_DHE_DSS_WITH_AES_256_GCM_SHA384','DHE-DSS-AES256-GCM-SHA384','TLS1.2'],
            ['0x00A4','NR','TLS_DH_DSS_WITH_AES_128_GCM_SHA256','DH-DSS-AES128-GCM-SHA256','TLS1.2'],
            ['0x00A5','NR','TLS_DH_DSS_WITH_AES_256_GCM_SHA384','DH-DSS-AES256-GCM-SHA384','TLS1.2'],
            ['0x00A6','NR','TLS_DH_anon_WITH_AES_128_GCM_SHA256','ADH-AES128-GCM-SHA256','TLS1.2'],
            ['0x00A7','NR','TLS_DH_anon_WITH_AES_256_GCM_SHA384','ADH-AES256-GCM-SHA384','TLS1.2'],
            ['0x00A8','NR','TLS_PSK_WITH_AES_128_GCM_SHA256','none','TLS1.2'],
            ['0x00A9','NR','TLS_PSK_WITH_AES_256_GCM_SHA384','none','TLS1.2'],
            ['0x00AA','NR','TLS_DHE_PSK_WITH_AES_128_GCM_SHA256','none','TLS1.2'],
            ['0x00AB','NR','TLS_DHE_PSK_WITH_AES_256_GCM_SHA384','none','TLS1.2'],
            ['0x00AC','NR','TLS_RSA_PSK_WITH_AES_128_GCM_SHA256','none','TLS1.2'],
            ['0x00AD','NR','TLS_RSA_PSK_WITH_AES_256_GCM_SHA384','none','TLS1.2'],
            ['0x00AE','NR','TLS_PSK_WITH_AES_128_CBC_SHA256','none','TLS1.2'],
            ['0x00AF','NR','TLS_PSK_WITH_AES_256_CBC_SHA384','none','TLS1.2'],
            ['0x00B0','NR','TLS_PSK_WITH_NULL_SHA256','none','TLS1.2'],
            ['0x00B1','NR','TLS_PSK_WITH_NULL_SHA384','none','TLS1.2'],
            ['0x00B2','NR','TLS_DHE_PSK_WITH_AES_128_CBC_SHA256','none','TLS1.2'],
            ['0x00B3','NR','TLS_DHE_PSK_WITH_AES_256_CBC_SHA384','none','TLS1.2'],
            ['0x00B4','NR','TLS_DHE_PSK_WITH_NULL_SHA256','none','TLS1.2'],
            ['0x00B5','NR','TLS_DHE_PSK_WITH_NULL_SHA384','none','TLS1.2'],
            ['0x00B6','NR','TLS_RSA_PSK_WITH_AES_128_CBC_SHA256','none','TLS1.2'],
            ['0x00B7','NR','TLS_RSA_PSK_WITH_AES_256_CBC_SHA384','none','TLS1.2'],
            ['0x00B8','NR','TLS_RSA_PSK_WITH_NULL_SHA256','none','TLS1.2'],
            ['0x00B9','NR','TLS_RSA_PSK_WITH_NULL_SHA384','none','TLS1.2'],
            ['0x00BA','NR','TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256','CAMELLIA128-SHA256','TLS1.2'],
            ['0x00BB','NR','TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256','DH-DSS-CAMELLIA128-SHA256','TLS1.2'],
            ['0x00BC','NR','TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256','DH-RSA-CAMELLIA128-SHA256','TLS1.2'],
            ['0x00BD','NR','TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256','DHE-DSS-CAMELLIA128-SHA256','TLS1.2'],
            ['0x00BE','NR','TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256','DHE-RSA-CAMELLIA128-SHA256','TLS1.2'],
            ['0x00BF','NR','TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256','ADH-CAMELLIA128-SHA256','TLS1.2'],
            ['0x00C0','NR','TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256','none','TLS1.2'],
            ['0x00C1','NR','TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256','none','TLS1.2'],
            ['0x00C2','NR','TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256','none','TLS1.2'],
            ['0x00C3','NR','TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256','none','TLS1.2'],
            ['0x00C4','NR','TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256','none','TLS1.2'],
            ['0x00C5','NR','TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256','none','TLS1.2'],
            ['0x00C6','NR','TLS_SM4_GCM_SM3','none','TLS1.2'],
            ['0x00C7','NR','TLS_SM4_CCM_SM3','none','TLS1.2'],
            ['0x00FF','NR','TLS_EMPTY_RENEGOTIATION_INFO_SCSV','none','TLS1.2'],
            ['0x5600','NR','TLS_FALLBACK_SCSV','TLS_FALLBACK_SCSV','TLS1.2'],
            ['0xC001','NR','TLS_ECDH_ECDSA_WITH_NULL_SHA','ECDH-ECDSA-NULL-SHA','TLS1.2'],
            ['0xC002','NR','TLS_ECDH_ECDSA_WITH_RC4_128_SHA','ECDH-ECDSA-RC4-SHA','TLS1.2'],
            ['0xC003','NR','TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA','ECDH-ECDSA-DES-CBC3-SHA','TLS1.2'],
            ['0xC004','NR','TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA','ECDH-ECDSA-AES128-SHA','TLS1.2'],
            ['0xC005','NR','TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA','ECDH-ECDSA-AES256-SHA','TLS1.2'],
            ['0xC006','NR','TLS_ECDHE_ECDSA_WITH_NULL_SHA','ECDHE-ECDSA-NULL-SHA','TLS1.2'],
            ['0xC007','NR','TLS_ECDHE_ECDSA_WITH_RC4_128_SHA','ECDHE-ECDSA-RC4-SHA','TLS1.2'],
            ['0xC008','NR','TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA','ECDHE-ECDSA-DES-CBC3-SHA','TLS1.2'],
            ['0xC009','NR','TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA','ECDHE-ECDSA-AES128-SHA','TLS1.2'],
            ['0xC00A','NR','TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA','ECDHE-ECDSA-AES256-SHA','TLS1.2'],
            ['0xC00B','NR','TLS_ECDH_RSA_WITH_NULL_SHA','ECDH-RSA-NULL-SHA','TLS1.2'],
            ['0xC00C','NR','TLS_ECDH_RSA_WITH_RC4_128_SHA','ECDH-RSA-RC4-SHA','TLS1.2'],
            ['0xC00D','NR','TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA','ECDH-RSA-DES-CBC3-SHA','TLS1.2'],
            ['0xC00E','NR','TLS_ECDH_RSA_WITH_AES_128_CBC_SHA','ECDH-RSA-AES128-SHA','TLS1.2'],
            ['0xC00F','NR','TLS_ECDH_RSA_WITH_AES_256_CBC_SHA','ECDH-RSA-AES256-SHA','TLS1.2'],
            ['0xC010','NR','TLS_ECDHE_RSA_WITH_NULL_SHA','ECDHE-RSA-NULL-SHA','TLS1.2'],
            ['0xC011','NR','TLS_ECDHE_RSA_WITH_RC4_128_SHA','ECDHE-RSA-RC4-SHA','TLS1.2'],
            ['0xC012','NR','TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA','ECDHE-RSA-DES-CBC3-SHA','TLS1.2'],
            ['0xC013','NR','TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA','ECDHE-RSA-AES128-SHA','TLS1.2'],
            ['0xC014','NR','TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA','ECDHE-RSA-AES256-SHA','TLS1.2'],
            ['0xC015','NR','TLS_ECDH_anon_WITH_NULL_SHA','AECDH-NULL-SHA','TLS1.2'],
            ['0xC016','NR','TLS_ECDH_anon_WITH_RC4_128_SHA','AECDH-RC4-SHA','TLS1.2'],
            ['0xC017','NR','TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA','AECDH-DES-CBC3-SHA','TLS1.2'],
            ['0xC018','NR','TLS_ECDH_anon_WITH_AES_128_CBC_SHA','AECDH-AES128-SHA','TLS1.2'],
            ['0xC019','NR','TLS_ECDH_anon_WITH_AES_256_CBC_SHA','AECDH-AES256-SHA','TLS1.2'],
            ['0xC01A','NR','TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA','SRP-3DES-EDE-CBC-SHA','TLS1.2'],
            ['0xC01B','NR','TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA','SRP-RSA-3DES-EDE-CBC-SHA','TLS1.2'],
            ['0xC01C','NR','TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA','SRP-DSS-3DES-EDE-CBC-SHA','TLS1.2'],
            ['0xC01D','NR','TLS_SRP_SHA_WITH_AES_128_CBC_SHA','SRP-AES-128-CBC-SHA','TLS1.2'],
            ['0xC01E','NR','TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA','SRP-RSA-AES-128-CBC-SHA','TLS1.2'],
            ['0xC01F','NR','TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA','SRP-DSS-AES-128-CBC-SHA','TLS1.2'],
            ['0xC020','NR','TLS_SRP_SHA_WITH_AES_256_CBC_SHA','SRP-AES-256-CBC-SHA','TLS1.2'],
            ['0xC021','NR','TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA','SRP-RSA-AES-256-CBC-SHA','TLS1.2'],
            ['0xC022','NR','TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA','SRP-DSS-AES-256-CBC-SHA','TLS1.2'],
            ['0xC025','NR','TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256','ECDH-ECDSA-AES128-SHA256','TLS1.2'],
            ['0xC026','NR','TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384','ECDH-ECDSA-AES256-SHA384','TLS1.2'],
            ['0xC029','NR','TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256','ECDH-RSA-AES128-SHA256','TLS1.2'],
            ['0xC02A','NR','TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384','ECDH-RSA-AES256-SHA384','TLS1.2'],
            ['0xC02D','NR','TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256','ECDH-ECDSA-AES128-GCM-SHA256','TLS1.2'],
            ['0xC02E','NR','TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384','ECDH-ECDSA-AES256-GCM-SHA384','TLS1.2'],
            ['0xC031','NR','TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256','ECDH-RSA-AES128-GCM-SHA256','TLS1.2'],
            ['0xC032','NR','TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384','ECDH-RSA-AES256-GCM-SHA384','TLS1.2'],
            ['0xC033','NR','TLS_ECDHE_PSK_WITH_RC4_128_SHA','ECDHE-PSK-RC4-SHA','TLS1.2'],
            ['0xC034','NR','TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA','ECDHE-PSK-3DES-EDE-CBC-SHA','TLS1.2'],
            ['0xC035','NR','TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA','ECDHE-PSK-AES128-CBC-SHA','TLS1.2'],
            ['0xC036','NR','TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA','ECDHE-PSK-AES256-CBC-SHA','TLS1.2'],
            ['0xC037','NR','TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256','ECDHE-PSK-AES128-CBC-SHA256','TLS1.2'],
            ['0xC038','NR','TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384','ECDHE-PSK-AES256-CBC-SHA384','TLS1.2'],
            ['0xC039','NR','TLS_ECDHE_PSK_WITH_NULL_SHA','ECDHE-PSK-NULL-SHA','TLS1.2'],
            ['0xC03A','NR','TLS_ECDHE_PSK_WITH_NULL_SHA256','ECDHE-PSK-NULL-SHA256','TLS1.2'],
            ['0xC03B','NR','TLS_ECDHE_PSK_WITH_NULL_SHA384','ECDHE-PSK-NULL-SHA384','TLS1.2'],
            ['0xC03C','NR','TLS_RSA_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC03D','NR','TLS_RSA_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC03E','NR','TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC03F','NR','TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC040','NR','TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC041','NR','TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC042','NR','TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC043','NR','TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC044','NR','TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC045','NR','TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC046','NR','TLS_DH_anon_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC047','NR','TLS_DH_anon_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC048','NR','TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC049','NR','TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC04A','NR','TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC04B','NR','TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC04C','NR','TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC04D','NR','TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC04E','NR','TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC04F','NR','TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC050','NR','TLS_RSA_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC051','NR','TLS_RSA_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC052','NR','TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC053','NR','TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC054','NR','TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC055','NR','TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC056','NR','TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC057','NR','TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC058','NR','TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC059','NR','TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC05A','NR','TLS_DH_anon_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC05B','NR','TLS_DH_anon_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC05C','NR','TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC05D','NR','TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC05E','NR','TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC05F','NR','TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC060','NR','TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC061','NR','TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC062','NR','TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC063','NR','TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC064','NR','TLS_PSK_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC065','NR','TLS_PSK_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC066','NR','TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC067','NR','TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC068','NR','TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC069','NR','TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC06A','NR','TLS_PSK_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC06B','NR','TLS_PSK_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC06C','NR','TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC06D','NR','TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC06E','NR','TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC06F','NR','TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC070','NR','TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256','none','TLS1.2'],
            ['0xC071','NR','TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384','none','TLS1.2'],
            ['0xC072','NR','TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256','ECDHE-ECDSA-CAMELLIA128-SHA256','TLS1.2'],
            ['0xC073','NR','TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384','ECDHE-ECDSA-CAMELLIA256-SHA38','TLS1.2'],
            ['0xC074','NR','TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256','ECDH-ECDSA-CAMELLIA128-SHA256','TLS1.2'],
            ['0xC075','NR','TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384','ECDH-ECDSA-CAMELLIA256-SHA384','TLS1.2'],
            ['0xC076','NR','TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256','ECDHE-RSA-CAMELLIA128-SHA256','TLS1.2'],
            ['0xC077','NR','TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384','ECDHE-RSA-CAMELLIA256-SHA384','TLS1.2'],
            ['0xC078','NR','TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256','ECDH-RSA-CAMELLIA128-SHA256','TLS1.2'],
            ['0xC079','NR','TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384','ECDH-RSA-CAMELLIA256-SHA384','TLS1.2'],
            ['0xC07A','NR','TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC07B','NR','TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC07C','NR','TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC07D','NR','TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC07E','NR','TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC07F','NR','TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC080','NR','TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC081','NR','TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC082','NR','TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC083','NR','TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC084','NR','TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC085','NR','TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC086','NR','TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC087','NR','TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC088','NR','TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC089','NR','TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC08A','NR','TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC08B','NR','TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC08C','NR','TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC08D','NR','TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC08E','NR','TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC08F','NR','TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC090','NR','TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC091','NR','TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC092','NR','TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256','none','TLS1.2'],
            ['0xC093','NR','TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384','none','TLS1.2'],
            ['0xC094','NR','TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256','PSK-CAMELLIA128-SHA256','TLS1.2'],
            ['0xC095','NR','TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384','PSK-CAMELLIA256-SHA384','TLS1.2'],
            ['0xC096','NR','TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256','DHE-PSK-CAMELLIA128-SHA256','TLS1.2'],
            ['0xC097','NR','TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384','DHE-PSK-CAMELLIA256-SHA384','TLS1.2'],
            ['0xC098','NR','TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256','RSA-PSK-CAMELLIA128-SHA256','TLS1.2'],
            ['0xC099','NR','TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384','RSA-PSK-CAMELLIA256-SHA384','TLS1.2'],
            ['0xC09A','NR','TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256','ECDHE-PSK-CAMELLIA128-SHA256','TLS1.2'],
            ['0xC09B','NR','TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384','ECDHE-PSK-CAMELLIA256-SHA384','TLS1.2'],
            ['0xC0A0','NR','TLS_RSA_WITH_AES_128_CCM_8','AES128-CCM8','TLS1.2'],
            ['0xC0A1','NR','TLS_RSA_WITH_AES_256_CCM_8','AES256-CCM8','TLS1.2'],
            ['0xC0A2','NR','TLS_DHE_RSA_WITH_AES_128_CCM_8','DHE-RSA-AES128-CCM8','TLS1.2'],
            ['0xC0A3','NR','TLS_DHE_RSA_WITH_AES_256_CCM_8','DHE-RSA-AES256-CCM8','TLS1.2'],
            ['0xC0A4','NR','TLS_PSK_WITH_AES_128_CCM','PSK-AES128-CCM','TLS1.2'],
            ['0xC0A5','NR','TLS_PSK_WITH_AES_256_CCM','PSK-AES256-CCM','TLS1.2'],
            ['0xC0A6','NR','TLS_DHE_PSK_WITH_AES_128_CCM','DHE-PSK-AES128-CCM','TLS1.2'],
            ['0xC0A7','NR','TLS_DHE_PSK_WITH_AES_256_CCM','DHE-PSK-AES256-CCM','TLS1.2'],
            ['0xC0A8','NR','TLS_PSK_WITH_AES_128_CCM_8','PSK-AES128-CCM8','TLS1.2'],
            ['0xC0A9','NR','TLS_PSK_WITH_AES_256_CCM_8','PSK-AES256-CCM8','TLS1.2'],
            ['0xC0AA','NR','TLS_PSK_DHE_WITH_AES_128_CCM_8','DHE-PSK-AES128-CCM8','TLS1.2'],
            ['0xC0AB','NR','TLS_PSK_DHE_WITH_AES_256_CCM_8','DHE-PSK-AES256-CCM8','TLS1.2'],
            ['0xC0AE','NR','TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8','ECDHE-ECDSA-AES128-CCM8','TLS1.2'],
            ['0xC0AF','NR','TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8','ECDHE-ECDSA-AES256-CCM8','TLS1.2'],
            ['0xC0B0','NR','TLS_ECCPWD_WITH_AES_128_GCM_SHA256','none','TLS1.2'],
            ['0xC0B1','NR','TLS_ECCPWD_WITH_AES_256_GCM_SHA384','none','TLS1.2'],
            ['0xC0B2','NR','TLS_ECCPWD_WITH_AES_128_CCM_SHA256','none','TLS1.2'],
            ['0xC0B3','NR','TLS_ECCPWD_WITH_AES_256_CCM_SHA384','none','TLS1.2'],
            ['0xC0B4','NR','TLS_SHA256_SHA256','none','TLS1.2'],
            ['0xC0B5','NR','TLS_SHA384_SHA384','none','TLS1.2'],
            ['0xC100','NR','TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC','none','TLS1.2'],
            ['0xC101','NR','TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC','none','TLS1.2'],
            ['0xC102','NR','TLS_GOSTR341112_256_WITH_28147_CNT_IMIT','none','TLS1.2'],
            ['0xC103','NR','TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L','none','TLS1.2'],
            ['0xC104','NR','TLS_GOSTR341112_256_WITH_MAGMA_MGM_L','none','TLS1.2'],
            ['0xC105','NR','TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S','none','TLS1.2'],
            ['0xC106','NR','TLS_GOSTR341112_256_WITH_MAGMA_MGM_S','none','TLS1.2'],
            ['0xCCAA','NR','TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256','DHE-RSA-CHACHA20-POLY1305','TLS1.2'],
            ['0xCCAB','NR','TLS_PSK_WITH_CHACHA20_POLY1305_SHA256','PSK-CHACHA20-POLY1305','TLS1.2'],
            ['0xCCAC','NR','TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256','ECDHE-PSK-CHACHA20-POLY1305','TLS1.2'],
            ['0xCCAD','NR','TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256','DHE-PSK-CHACHA20-POLY1305','TLS1.2'],
            ['0xCCAE','NR','TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256','RSA-PSK-CHACHA20-POLY1305','TLS1.2'],
            ['0xD001','NR','TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256','none','TLS1.2'],
            ['0xD002','NR','TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384','none','TLS1.2'],
            ['0xD003','NR','TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256','none','TLS1.2'],
            ['0xD005','NR','TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256','none','TLS1.2']])
"""

    
  