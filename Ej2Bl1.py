#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import sys
import ConfigParser
from argparse import ArgumentParser
from modules.nmapreq import nmap_analisis

if __name__ == '__main__':

    config = ConfigParser.ConfigParser()
    config.read('config.cfg')

    argp = ArgumentParser(version='Versión del script: 1.1', description=' \
    Dada una dirección IP o un nombre de dominio, encontrar información \
    relacionada con el propietario de dicho dominio y los registros DNS \
    correspondientes.')

    argp.add_argument('-nm', '--scannmap', action='store', required=True,
                      help='Escaneo con Nmap')

    args = argp.parse_args()

    if args.scannmap:
        nmap_analisis(args.scannmap)
    else:
        sys.exit(0)
