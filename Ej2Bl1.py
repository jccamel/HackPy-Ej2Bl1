#!/usr/bin/env python
# -*- encoding: utf-8 -*-

# blanes.cat 195.76.254.114

from argparse import ArgumentParser
import requests


class DomainData(object):

    def __init__(self, domain):
        self.target = domain
        self.metodos = ''

    def __del__(self):
        pass

    def nmap_analisis(self):
        import nmap
        """
        Dada una dirección IP, ejecutar un escaneo con Nmap contra el objetivo de forma programática.
        """
        webserver_list = {80: 'http://', 8080: 'http://', 8443: 'https://', 443: 'https://', 10000: 'https://'}
        nm = nmap.PortScanner()
        nm.scan(self.target, '80, 443, 8080, 8443, 10000', arguments="-n -sT")
        for host in nm.all_hosts():
            print ("Servidor: %s" % host)
            print (" Puertos:")
            for puerto in nm[host]['tcp'].keys():
                print ("  [*] %s:" % puerto)
                for k, v in nm[host]['tcp'][int(puerto)].iteritems():
                    """
                    En el caso de encontrar puertos que frecuentemente se
                    relacionan con servidores web (80, 8080, 443, 10000) realizar
                    una petición HTTP utilizando el método OPTIONS para determinar
                    si efectivamente, el objetivo es un servidor web y extraer los
                    métodos HTTP soportados.
                    """
                    if (int(puerto) in webserver_list) and (v == 'open'):
                        verbs = requests.options(webserver_list[int(puerto)] + self.target + ':' + str(puerto))
                        print ('        Web: %s' % webserver_list[int(puerto)] + self.target + ":" + str(puerto))
                        print ('          Status Code: %s' % str(verbs.status_code))
                        if int(verbs.status_code) == 200:
                            try:
                                print ('          Methods: %s' % str(verbs.headers['allow']))
                            except:
                                print '           No Methods'
                    # ----------------------------------------------------------------------------------------------
                    print ('        {}: {}'.format(k, v))


if __name__ == '__main__':

    argp = ArgumentParser(version='Versión del script: 1.1', description=' \
    Dada una dirección IP o un nombre de dominio, encontrar información \
    relacionada con el propietario de dicho dominio y los registros DNS \
    correspondientes.')

    argp.add_argument('-nm', '--scannmap', action='store', required=True,
                      help='Escaneo con Nmap')

    args = argp.parse_args()

    d = DomainData(args.scannmap)
    d.nmap_analisis()

    del d
