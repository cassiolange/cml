import os
import sys
import netmiko
import multiprocessing
import time
import pandas
import virl2_client
import cml_config


if __name__ == '__main__':
    start = time.time()
    cml_conn = virl2_client.ClientLibrary(cml_config.cml_server, cml_config.user, cml_config.password, ssl_verify=False)
    lab = cml_conn.find_labs_by_title(cml_config.labname)
    join_lab = cml_conn.join_existing_lab(lab[0].id)

    processes = []
    for i in join_lab.nodes():
        if i.node_definition != 'unmanaged_switch' and i.node_definition != 'external_connector':
            print(i.label)
            processes.append(multiprocessing.Process(target=i.extract_configuration, args=()))
    for p in processes:
        p.start()
    for p in processes:
        p.join()

    backup = join_lab.download()
    date = time.strftime('%d_%m_%Y_%H_%m_%S')
    backup_file = cml_config.input_source + cml_config.labname + '/backup_'+date+'.yaml'
    file = open(backup_file,'w')
    file.write(backup)
    file.close()

    print("Elapsed time %s" % str(time.time()-start))
