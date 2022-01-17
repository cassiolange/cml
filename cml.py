import os
import sys
import pandas
import multiprocessing
import time
import re
import virl2_client
import ipaddress
import yaml
import cml_config
import glob

def execute_config_nxos(routers, i):
    cml_conn = virl2_client.ClientLibrary(cml_config.cml_server, cml_config.user, cml_config.password, ssl_verify=False)
    lab = cml_conn.find_labs_by_title(cml_config.labname)
    join_lab = cml_conn.join_existing_lab(lab[0].id)
    node = join_lab.get_node_by_label(routers[i]['name'])
    config = []
    print("Starting configuring the %s" % routers[i]['name'])
    config.append('hostname ' + routers[i]['name'])
    config.append('no ip domain-lookup ')
    config.append('no password strength-check')
    config.append('username %s password %s role network-admin' %(routers[i]['username'], routers[i]['password']))
    config.append('username cisco password cisco role network-admin')
    config.append('int mgmt0')
    config.append(' ip add ' + routers[i]['interfaces'][2]['ip'])
    config.append(' no shutdown')
    config.append('vrf context management')
    config.append('ip route 0.0.0.0/0 %s' % routers[i]['mgmt_gw'])
    config.append('system default switchport')
    config.append('system default switchport shutdown')
    config.append('boot nxos bootflash:nxos.9.3.6.bin')

    config2=''

    for y in range(len(config)):
        config2 = config2 + (config[y]+'\n')
    node.config = config2

    print("Finished the configure %s" % routers[i]['name'])

def execute_config_xr(routers,i):
    cml_conn = virl2_client.ClientLibrary(cml_config.cml_server, cml_config.user, cml_config.password, ssl_verify=False)
    lab = cml_conn.find_labs_by_title(cml_config.labname)
    join_lab = cml_conn.join_existing_lab(lab[0].id)
    node = join_lab.get_node_by_label(routers[i]['name'])
    config = []
    print("Starting configuring the %s" % routers[i]['name'])
    config.append('hostname ' + routers[i]['name'])
    config.append('no ip domain-lookup ')
    config.append('username %s' % routers[i]['username'])
    config.append('group root-lr')
    config.append('group cisco-support')
    config.append('password %s' % routers[i]['password'])
    config.append('!')
    config.append('username cisco')
    config.append('group root-lr')
    config.append('group cisco-support')
    config.append('password cisco')
    config.append('!')
    config.append('logging on')
    config.append('logging console debugging')
    config.append('!')
    for k in routers[i]['interfaces']:
        if 'vrf' in routers[i]['interfaces'][k]:
            config.append('vrf ' + routers[i]['interfaces'][k]['vrf'])
        if 'vlan' in routers[i]['interfaces'][k]:
            config.append('interface ' + routers[i]['interfaces'][k]['parent_interface'])
            config.append('no shutdown')
        config.append('interface ' + routers[i]['interfaces'][k]['interface'])
        if 'vrf' in routers[i]['interfaces'][k]:
            config.append('vrf ' + routers[i]['interfaces'][k]['vrf'])
        if 'vlan' in routers[i]['interfaces'][k]:
            config.append('encapsulation dot1q ' + routers[i]['interfaces'][k]['vlan'])
        config.append('ipv4 add ' + routers[i]['interfaces'][k]['ip'])
        config.append('ipv6 add ' + routers[i]['interfaces'][k]['ipv6'])
        config.append('no shut')
        config.append('root')
        if 'ospf' in routers[i]['interfaces'][k]:
            if routers[i]['interfaces'][k]['interface'] != 'lo0':
                config.append('router ospf %s area %s interface %s network point-to-point ' % (str(routers[i]['interfaces'][k]['ospf']['id']), str(routers[i]['interfaces'][k]['ospf']['area']), str(routers[i]['interfaces'][k]['interface'])))
                config.append('router ospfv3 %s area %s interface %s network point-to-point ' % (str(routers[i]['interfaces'][k]['ospf']['id']), str(routers[i]['interfaces'][k]['ospf']['area']), str(routers[i]['interfaces'][k]['interface'])))
                # config.append('root')
            else:
                config.append('router ospf %s area %s interface %s' % (str(routers[i]['interfaces'][k]['ospf']['id']), str(routers[i]['interfaces'][k]['ospf']['area']), str(routers[i]['interfaces'][k]['interface'])))
                config.append('router ospfv3 %s area %s interface %s' % (str(routers[i]['interfaces'][k]['ospf']['id']), str(routers[i]['interfaces'][k]['ospf']['area']), str(routers[i]['interfaces'][k]['interface'])))
                config.append('root')
    if 'ldp-ospf' in routers[i]:
        config.append('mpls ldp router-id %s' % (str(routers[i]['interfaces'][1]['ip']).split()[0]))
        # print(routers[i]['interfaces'][1]['ip'])
        config.append('router ospf  ' + str(routers[i]['interfaces'][1]['ospf']['id']))
        config.append('mpls ldp auto-config')
    config.append('commit')
    config.append('router static vrf mgmt address-family ipv4 unicast 0.0.0.0/0 %s' % routers[i]['mgmt_gw'])
    config.append('ssh server vrf mgmt')
    config.append('do crypto key generate ecdsa nistp256')
    config2 = ''
    for y in range(len(config)):
        config2 = config2 + (config[y] + '\n')
    node.config = config2

    print("Finished the configure %s" % routers[i]['name'])

def execute_config_ios(routers,i):
    cml_conn = virl2_client.ClientLibrary(cml_config.cml_server, cml_config.user, cml_config.password, ssl_verify=False)
    lab = cml_conn.find_labs_by_title(cml_config.labname)
    join_lab = cml_conn.join_existing_lab(lab[0].id)
    node = join_lab.get_node_by_label(routers[i]['name'])
    config = []
    print("Starting configuring the %s" % routers[i]['name'])
    config.append('hostname ' + routers[i]['name'])
    config.append('ipv6 unicast-routing')
    config.append('no ip domain lookup ')
    config.append('ip domain name cassio.lab')
    config.append('crypto key generate rsa modulus 2048')
    config.append('line vty 0 15')
    config.append('transport input all')
    config.append('login local')
    config.append('username %s privilege 15 password %s' %(routers[i]['username'], routers[i]['password']))
    config.append('username cisco privilege 15 password cisco')
    for k in routers[i]['interfaces']:
        if 'vrf' in routers[i]['interfaces'][k]:
            config.append('vrf definition ' + routers[i]['interfaces'][k]['vrf'])
            config.append('address-family ipv4')
            config.append('address-family ipv6')
        if 'vlan' in routers[i]['interfaces'][k]:
            config.append('interface ' + routers[i]['interfaces'][k]['parent_interface'])
            config.append('no shutdown')
        config.append('interface ' + routers[i]['interfaces'][k]['interface'])
        if 'vrf' in routers[i]['interfaces'][k]:
            config.append('vrf forwarding ' + routers[i]['interfaces'][k]['vrf'])
        if routers[i]['device'] == 'Switch L3' and routers[i]['interfaces'] != 'lo0':
            config.append('no switchport')
        if 'vlan' in routers[i]['interfaces'][k]:
            config.append('encapsulation dot1q ' + routers[i]['interfaces'][k]['vlan'])
        config.append('ip add ' + routers[i]['interfaces'][k]['ip'])
        config.append('ipv6 add ' + routers[i]['interfaces'][k]['ipv6'])

        if 'ospf' in routers[i]['interfaces'][k]:
            config.append('ip ospf %s area %s' % (
                str(routers[i]['interfaces'][k]['ospf']['id']),
                str(routers[i]['interfaces'][k]['ospf']['area'])))
            config.append('ospfv3 %s ipv6 area %s' % (
                str(routers[i]['interfaces'][k]['ospf']['id']), str(routers[i]['interfaces'][k]['ospf']['area'])))
            if routers[i]['interfaces'][k]['interface'] != 'lo0':
                config.append('ip ospf network point-to-point')
                config.append('ospfv3 %s ipv6 network point-to-point' % str(routers[i]['interfaces'][k]['ospf']['id']))
        config.append('no shut')
    if 'ldp-ospf' in routers[i]:
        config.append('mpls ldp router-id lo0 force')
        config.append('router ospf  ' + str(routers[i]['interfaces'][1]['ospf']['id']))
        config.append('mpls ldp autoconfig')
    config.append('ip route vrf mgmt 0.0.0.0 0.0.0.0 %s' % routers[i]['mgmt_gw'])
    config2=''

    for y in range(len(config)):
        config2 = config2 + (config[y]+'\n')
    node.config = config2

    print("Finished the configure %s" % routers[i]['name'])

def create_lab():
    #login no eve
    cml_conn = virl2_client.ClientLibrary(cml_config.cml_server, cml_config.user, cml_config.password, ssl_verify=False)
    #create the lab
    lab = cml_conn.create_lab(cml_config.labname)
    #check if the lab already exist
    #if createlab['code'] != 200:
    #    print(createlab["message"])
    #    exit(0)

    join_lab = cml_conn.join_existing_lab(lab.id)
    #Open excel file, sheet router definition
    excel = pandas.read_excel(cml_config.input_excel_file, sheet_name='Routers')
    #Read routers and eve port from XLSX file and add to dictionary
    for i in excel.index:
        #print (excel['PORT'][i])
        #node = eveapi.findnode(eve, evelogin, labname, excel['HOSTNAME'][i])
        if excel['NODE_TYPE'][i] == 'IOL':
            node = join_lab.create_node(label=excel['HOSTNAME'][i], node_definition='iosv', populate_interfaces=False)
            for z in range(7):
                node.create_interface()
            if excel['VERSION'].isnull()[i] == False:
                node.image_definition = excel['VERSION'][i]
        if excel['NODE_TYPE'][i] == 'CSR':
            node = join_lab.create_node(label=excel['HOSTNAME'][i], node_definition='csr1000v', populate_interfaces=True)
            for z in range(7):
                node.create_interface()
            if excel['VERSION'].isnull()[i] == False:
                node.image_definition = excel['VERSION'][i]
        if excel['NODE_TYPE'][i] == 'XR':
            node = join_lab.create_node(label=excel['HOSTNAME'][i], node_definition='iosxrv', populate_interfaces=True)
            for z in range(7):
                node.create_interface()
            if excel['VERSION'].isnull()[i] == False:
                node.image_definition = excel['VERSION'][i]
        if excel['NODE_TYPE'][i] == 'XR9KV':
            node = join_lab.create_node(label=excel['HOSTNAME'][i], node_definition='iosxrv9000', populate_interfaces=True)
            for z in range(7):
                node.create_interface()
            if excel['VERSION'].isnull()[i] == False:
                node.image_definition = excel['VERSION'][i]
        if excel['NODE_TYPE'][i] == 'CAT8KV':
            node = join_lab.create_node(label=excel['HOSTNAME'][i], node_definition='C8000v', populate_interfaces=True)
            for z in range(5):
                node.create_interface()
            if excel['VERSION'].isnull()[i] == False:
                node.image_definition = excel['VERSION'][i]
        if excel['NODE_TYPE'][i] == 'NXOS':
            node = join_lab.create_node(label=excel['HOSTNAME'][i], node_definition='nxosv9000', populate_interfaces=True)
            for z in range(5):
                node.create_interface()
            if excel['VERSION'].isnull()[i] == False:
                node.image_definition = excel['VERSION'][i]

    mgmt_switch = join_lab.create_node(label='mgmt_switch', node_definition='unmanaged_switch', populate_interfaces=True, wait=True)
    for z in range(20):
        mgmt_switch.create_interface()
    mgmt_external = join_lab.create_node(label='mgmt', node_definition='external_connector', populate_interfaces=True, wait=True)
    time.sleep(1)
    link = join_lab.create_link(i1=mgmt_switch.next_available_interface(), i2=mgmt_external.next_available_interface())
    mgmt_external.config = 'bridge0'


    """
    excel = pandas.read_excel(input_excel_file, sheet_name='Connections')

    for i in excel.index:
        if excel['LINK TYPE'][i] == "cloud":
            eveapi.addlinktonode(eve, evelogin, labname, excel['ROUTER1'][i], networkid['data']['id'],
                                 excel['INTERFACE1'][i])
            eveapi.addlinktonode(eve, evelogin, labname, excel['ROUTER2'][i], networkid['data']['id'],
                                 excel['INTERFACE2'][i])
        else:
            node_a = join_lab.get_node_by_label(excel['ROUTER1'][i])
            node_b = join_lab.get_node_by_label(excel['ROUTER2'][i])
            join_lab.create_link(i1=node_a.get_interface_by_label(str(excel['INTERFACE1'][i])), i2=node_b.get_interface_by_label(str(excel['INTERFACE2'][i])))
            #join_lab.connect_two_nodes(join_lab.get_node_by_label(excel['ROUTER1'][i]), join_lab.get_node_by_label(excel['ROUTER2'][i]))
    """
    print("Lab created")

def configure_routers():
    cml_conn = virl2_client.ClientLibrary(cml_config.cml_server, cml_config.user, cml_config.password, ssl_verify=False)
    lab = cml_conn.find_labs_by_title(cml_config.labname)
    join_lab = cml_conn.join_existing_lab(lab[0].id)
    router_number_pattern = r'[0-9]+'
    # Open excel file, sheet router definition
    excel = pandas.read_excel(cml_config.input_excel_file, sheet_name='Routers')
    # Declare router Dictionary
    routers = {}
    # Read routers and eve port from XLSX file and add to dictionary
    mgmt_switch = join_lab.get_node_by_label('mgmt_switch')


    for i in excel.index:
        # print (excel['PORT'][i])
        # node = eveapi.findnode(eve, evelogin, labname, excel['HOSTNAME'][i])

        # eveapi.addlinktonode(eve, evelogin, labname, excel['HOSTNAME'][i], networkid['data']['id'])
        # eveapi.startnode(eve, evelogin, labname, excel['HOSTNAME'][i])
        interface_ip = str(ipaddress.IPv4Interface(excel['MGMT_IP'][i])).split('/')[0] + ' ' + str(ipaddress.IPv4Interface(excel['MGMT_IP'][i]).with_netmask).split('/')[1]

        routers.update(
            {
                excel['HOSTNAME'][i]: {
                    'name': excel['HOSTNAME'][i],
                    'device': excel['NODE_TYPE'][i],
                    'mgmt_gw': excel['MGMT_GW'][i],
                    'username': excel['USERNAME'][i],
                    'password': excel['PASSWORD'][i],
                    'interfaces': {
                        1: {
                            'interface': 'lo0',
                            'ip': cml_config.base_ip + '.' + re.search(router_number_pattern, excel['HOSTNAME'][i]).group(
                                0) + '.' + re.search(router_number_pattern, excel['HOSTNAME'][i]).group(
                                0) + '.' + re.search(router_number_pattern, excel['HOSTNAME'][i]).group(
                                0) + ' 255.255.255.255',
                            'ipv6': cml_config.base_ipv6 + ':' + cml_config.base_ip + ':' + re.search(router_number_pattern,
                                                                                excel['HOSTNAME'][i]).group(
                                0) + ':' + re.search(router_number_pattern, excel['HOSTNAME'][i]).group(
                                0) + '::' + re.search(router_number_pattern, excel['HOSTNAME'][i]).group(0) + '/128'
                        },
                        2: {
                            'interface': excel['MGMT_INT'][i],
                            'ip': interface_ip,
                            'vrf': excel['MGMT_VRF'][i],
                            'ipv6': excel['MGMT_IPV6'][i],
                        }
                    }
                }
            }
        )
        if excel['LO0 OSPF ID'].isnull()[i] == False:
            routers[excel['HOSTNAME'][i]]['interfaces'][1]['ospf'] = {
                'id': int(excel['LO0 OSPF ID'][i]),
                'area': int(excel['LO0 OSPF AREA'][i])
            }
        # ADD VRF TO INTERFACE
        if excel['VRF'].isnull()[i] == False:
            routers[excel['HOSTNAME'][i]]['interfaces'][1]['vrf'] = excel['VRF'][i]

        if excel['LDP OSPF'][i] == 'YES':
            routers[excel['HOSTNAME'][i]]['ldp-ospf'] = 'True'

        if excel['NODE_TYPE'][i] == 'Switch L3':
            routers[excel['HOSTNAME'][i]]['interfaces'][len(routers[excel['HOSTNAME'][i]]['interfaces']) + 1] = {
                'interface': 'vlan ' + routers[excel['HOSTNAME'][i]]['name'][1:],
                'ip': cml_config.base_ip + '.' + routers[excel['HOSTNAME'][i]]['name'][1:] + '.0.' + routers[excel['HOSTNAME'][i]][
                                                                                              'name'][
                                                                                          1:] + ' 255.255.255.0',
                'ipv6': cml_config.base_ipv6 + ':' + cml_config.base_ip + ':' + routers[excel['HOSTNAME'][i]]['name'][1:] + '::' +
                        routers[excel['HOSTNAME'][i]]['name'][1:] + '/64'
            }
            routers[excel['HOSTNAME'][i]]['vlan'] = 'vlan ' + routers[excel['HOSTNAME'][i]]['name'][1:],
        node_b = join_lab.get_node_by_label(excel['HOSTNAME'][i])
        link = join_lab.create_link(i1=mgmt_switch.next_available_interface(), i2=node_b.get_interface_by_label(str(excel['MGMT_INT'][i])))

    #print (routers)
    # Read connections from execel file, calcule subnet and dictionary
    # IPV4 = BASE IPV4 + First Router + Second Router + 0/24
    # IPV6 = BASE IPV6 + BASE IPV4 + First Router + Second Router :: 0/64
    excel = pandas.read_excel(cml_config.input_excel_file, sheet_name='Connections')
    interface = { 'Interface1': [], 'Interface2': []}
    # eveapi.startnode(eve, evelogin, labname, excel['HOSTNAME'][i])
    for i in excel.index:

        id_router1 = int(re.search(router_number_pattern, routers[excel['ROUTER1'][i]]['name']).group(0))
        id_router2 = int(re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(0))
        if excel['LINK TYPE'][i] != 'p2p':
            if id_router1 > id_router2:
                vlan = str(id_router2) + str(id_router1)
            else:
                vlan = str(id_router1) + str(id_router2)
        #
        # Create Interface then add IPV4 and IPV6 ADD
        #link = join_lab.connect_two_nodes(join_lab.get_node_by_label(excel['ROUTER1'][i]), join_lab.get_node_by_label(excel['ROUTER2'][i]))
        #excel.INTERFACE1[i]=link.interface_a.label
        #excel.INTERFACE2[i]=link.interface_b.label
        node_a = join_lab.get_node_by_label(excel['ROUTER1'][i])
        node_b = join_lab.get_node_by_label(excel['ROUTER2'][i])
        print(excel['ROUTER1'][i])
        print(excel['INTERFACE1'][i])
        print(excel['ROUTER2'][i])
        print(excel['INTERFACE2'][i])


        link = join_lab.create_link(i1=node_a.get_interface_by_label(str(excel['INTERFACE1'][i])), i2=node_b.get_interface_by_label(str(excel['INTERFACE2'][i])))


        if excel['LINK TYPE'][i] == 'p2p':
                routers[excel['ROUTER1'][i]]['interfaces'][len(routers[excel['ROUTER1'][i]]['interfaces']) + 1] = {
                    'interface': excel['INTERFACE1'][i],
                    'ip': cml_config.base_ip + '.' + re.search(router_number_pattern, routers[excel['ROUTER1'][i]]['name']).group(
                        0) + '.' + re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(
                        0) + '.' + re.search(router_number_pattern, routers[excel['ROUTER1'][i]]['name']).group(
                        0) + ' 255.255.255.0',
                    'ipv6': cml_config.base_ipv6 + ':' + cml_config.base_ip + ':' + re.search(router_number_pattern,
                                                                        routers[excel['ROUTER1'][i]]['name']).group(
                        0) + ':' + re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(
                        0) + '::' + re.search(router_number_pattern, routers[excel['ROUTER1'][i]]['name']).group(0) + '/64',
                    'parent_interface': excel['INTERFACE1'][i],
                }
        else:
                routers[excel['ROUTER1'][i]]['interfaces'][len(routers[excel['ROUTER1'][i]]['interfaces']) + 1] = {
                    'interface': excel['INTERFACE1'][i] + '.' + vlan,
                    'ip': cml_config.base_ip + '.' + re.search(router_number_pattern, routers[excel['ROUTER1'][i]]['name']).group(
                        0) + '.' + re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(
                        0) + '.' + re.search(router_number_pattern, routers[excel['ROUTER1'][i]]['name']).group(
                        0) + ' 255.255.255.0',
                    'ipv6': cml_config.base_ipv6 + ':' + cml_config.base_ip + ':' + re.search(router_number_pattern,
                                                                        routers[excel['ROUTER1'][i]]['name']).group(
                        0) + ':' + re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(
                        0) + '::' + re.search(router_number_pattern, routers[excel['ROUTER1'][i]]['name']).group(0) + '/64',
                    'vlan': vlan,
                    'parent_interface': excel['INTERFACE1'][i],
                }
        # ADD VRF TO INTERFACE
        if excel['VRF1'].isnull()[i] == False:
            routers[excel['ROUTER1'][i]]['interfaces'][len(routers[excel['ROUTER1'][i]]['interfaces'])]['vrf'] = \
            excel['VRF1'][i]

        # Create Interface then add IPV4 and IPV6 ADD
        if excel['LINK TYPE'][i] == 'p2p':
            routers[excel['ROUTER2'][i]]['interfaces'][len(routers[excel['ROUTER2'][i]]['interfaces']) + 1] = {
                'interface': excel['INTERFACE2'][i],
                'ip': cml_config.base_ip + '.' + re.search(router_number_pattern, routers[excel['ROUTER1'][i]]['name']).group(
                    0) + '.' + re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(
                    0) + '.' + re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(
                    0) + ' 255.255.255.0',
                'ipv6': cml_config.base_ipv6 + ':' + cml_config.base_ip + ':' + re.search(router_number_pattern,
                                                                    routers[excel['ROUTER1'][i]]['name']).group(
                    0) + ':' + re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(
                    0) + '::' + re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(0) + '/64',
                'parent_interface':excel['INTERFACE2'][i],
            }
        else:
            routers[excel['ROUTER2'][i]]['interfaces'][len(routers[excel['ROUTER2'][i]]['interfaces']) + 1] = {
                'interface': excel['INTERFACE2'][i],
                'ip': cml_config.base_ip + '.' + re.search(router_number_pattern, routers[excel['ROUTER1'][i]]['name']).group(
                    0) + '.' + re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(
                    0) + '.' + re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(
                    0) + ' 255.255.255.0',
                'ipv6': cml_config.base_ipv6 + ':' + cml_config.base_ip + ':' + re.search(router_number_pattern,
                                                                    routers[excel['ROUTER1'][i]]['name']).group(
                    0) + ':' + re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(
                    0) + '::' + re.search(router_number_pattern, routers[excel['ROUTER2'][i]]['name']).group(0) + '/64',
                'parent_interface':excel['INTERFACE2'][i],
            }
        # ADD VRF TO INTERFACE
        if excel['VRF2'].isnull()[i] == False:
            routers[excel['ROUTER2'][i]]['interfaces'][len(routers[excel['ROUTER2'][i]]['interfaces'])]['vrf'] = \
            excel['VRF2'][i]

        if excel['OSPF ID'].isnull()[i] == False:
            routers[excel['ROUTER1'][i]]['interfaces'][len(routers[excel['ROUTER1'][i]]['interfaces'])]['ospf'] = {
                'id': int(excel['OSPF ID'][i]),
                'area': int(excel['AREA'][i])
            }
            routers[excel['ROUTER2'][i]]['interfaces'][len(routers[excel['ROUTER2'][i]]['interfaces'])]['ospf'] = {
                'id': int(excel['OSPF ID'][i]),
                'area': int(excel['AREA'][i])
            }
    ####write to excel files (in case of use auto connection feature)
    #excelwr = pandas.ExcelWriter(input_excel_file, mode='a')
    #excel.to_excel(excelwr,sheet_name='Connections',index=False)
    #excelwr.close()
    processes = []
    for i in routers:
        if routers[i]['device'] == 'XR' or routers[i]['device'] == 'XR9KV':
            processes.append(multiprocessing.Process(target=execute_config_xr, args=(routers, i)))
        elif routers[i]['device'] == 'NXOS':
            processes.append(multiprocessing.Process(target=execute_config_nxos, args=(routers, i)))
        else:
            processes.append(multiprocessing.Process(target=execute_config_ios, args=(routers, i)))

    for p in processes:
        p.start()

    for p in processes:
        p.join()

def generate_ansible_hosts():
    hosts = {
        'all': {
            'children':{
                'switches':{
                    'children':{
                        'switches_ios' : {'hosts': {}},
                        'nxos' : {'hosts': {}},
                    }
                },
                'routers':{
                    'children':{
                        'routers_ios' : {'hosts': {}},
                        'ios_xr' : {'hosts': {}},
                    }
                }
            }
        }
    }
    excel = pandas.read_excel(cml_config.input_excel_file, sheet_name='Routers')
    for line in excel.index:
        if excel['NODE_TYPE'][line] == 'NXOS':
            hosts['all']['children']['switches']['children']['nxos']['hosts'][excel['HOSTNAME'][line]] = {
                'ansible_host': str(excel['MGMT_IP'][line]).split('/')[0]
            }
            if excel['USERNAME'].isnull()[0] == False:
                hosts['all']['children']['switches']['children']['nxos']['hosts'][excel['HOSTNAME'][line]].update(
                    {
                        'ansible_user': excel['USERNAME'][0]
                    }
                )
            if excel['PASSWORD'].isnull()[0] == False:
                hosts['all']['children']['switches']['children']['nxos']['hosts'][excel['HOSTNAME'][line]].update(
                    {
                        'ansible_password': excel['PASSWORD'][0]
                    }
                )
        elif excel['NODE_TYPE'][line] == 'XR' or excel['NODE_TYPE'][line] == 'XR9KV':
            hosts['all']['children']['routers']['children']['ios_xr']['hosts'][excel['HOSTNAME'][line]] = {
                'ansible_host': str(excel['MGMT_IP'][line]).split('/')[0]
            }
            if excel['USERNAME'].isnull()[0] == False:
                hosts['all']['children']['routers']['children']['ios_xr']['hosts'][excel['HOSTNAME'][line]].update(
                    {
                        'ansible_user': excel['USERNAME'][0]
                    }
                )
            if excel['PASSWORD'].isnull()[0] == False:
                hosts['all']['children']['routers']['children']['ios_xr']['hosts'][excel['HOSTNAME'][line]].update(
                    {
                        'ansible_password': excel['PASSWORD'][0]
                    }
                )
        elif excel['DEVICE_TYPE'][line] == 'router':
            hosts['all']['children']['routers']['children']['routers_ios']['hosts'][excel['HOSTNAME'][line]] = {
                'ansible_host': str(excel['MGMT_IP'][line]).split('/')[0]
            }
            if excel['USERNAME'].isnull()[0] == False:
                hosts['all']['children']['routers']['children']['routers_ios']['hosts'][excel['HOSTNAME'][line]].update(
                    {
                        'ansible_user': excel['USERNAME'][0]
                    }
                )
            if excel['PASSWORD'].isnull()[0] == False:
                hosts['all']['children']['routers']['children']['routers_ios']['hosts'][excel['HOSTNAME'][line]].update(
                    {
                        'ansible_password': excel['PASSWORD'][0]
                    }
                )
        else:
            hosts['all']['children']['switches']['children']['switches_ios']['hosts'][excel['HOSTNAME'][line]] = {
                'ansible_host': str(excel['MGMT_IP'][line]).split('/')[0]
            }
            if excel['USERNAME'].isnull()[0] == False:
                hosts['all']['children']['routers']['children']['switches_ios']['hosts'][excel['HOSTNAME'][line]].update(
                    {
                        'ansible_user': excel['USERNAME'][0]
                    }
                )
            if excel['PASSWORD'].isnull()[0] == False:
                hosts['all']['children']['routers']['children']['switches_ios']['hosts'][excel['HOSTNAME'][line]].update(
                    {
                        'ansible_password': excel['PASSWORD'][0]
                    }
                )

    file = open('hosts.yml','w')
    yaml.safe_dump(hosts, file)
    file.close()

def node_and_image_upload():
    cml_conn = virl2_client.ClientLibrary(cml_config.cml_server, cml_config.user, cml_config.password, ssl_verify=False)
    nodes = glob.glob(cml_config.images_and_node_dir+"node_definitions/*.yaml")
    for node in nodes:
        node_def = open(node)
        try:
            cml_conn.definitions.upload_node_definition(node_def)
        except:
            print("Node already exist")
    images = glob.glob(cml_config.images_and_node_dir+"image_definitions/*.qcow2")
    for image in images:
        try:
            cml_conn.definitions.upload_image_file(image)
        except:
            print("Image already exist")
    images = glob.glob(cml_config.images_and_node_dir+"image_definitions/*.yaml")
    for image in images:
        image_def = open(image)
        try:
            cml_conn.definitions.upload_image_definition(image_def)
        except:
            print("Image already exist")


def main():
    start = time.time()
    configure_routers()
    create_lab()
    generate_ansible_hosts()
    # node_and_image_upload()
    print("Elapsed time %s" % str(time.time()-start))

if __name__ == '__main__':
    main()