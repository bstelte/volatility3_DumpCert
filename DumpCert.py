# bstelte (c) 2022 CertDump plugin
#
# parts of this code are reused from volatility3 plugin pslist and vadyarascan
# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterable, List, Tuple
import datetime
import requests
import base64

from volatility.framework import interfaces, renderers, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.plugins import yarascan
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows.extensions import pe
from volatility.plugins.windows import pslist, vadinfo

vollog = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    vollog.info("Python Yara module not found, plugin (and dependent plugins) not available")
    raise

try:
    from cryptography import x509
    import cryptography.hazmat.primitives.serialization.pkcs12
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.x509 import ocsp
    from cryptography.x509.ocsp import OCSPResponseStatus
    from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
    import ssl
except ImportError:
    vollog.info("Python cryptography and ssl module not found, plugin (and dependent plugins) not available")
    raise

class DumpCert(interfaces.plugins.PluginInterface):
    """Scans all the Virtual Address Descriptor memory maps using yara."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = "Memory layer for the kernel",
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),            
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.VersionRequirement(name = 'yarascanner', component = yarascan.YaraScanner,
                                            version = (2, 0, 0)),
            requirements.BooleanRequirement(name = 'dump',
                                            description = "Extract CERT to current folder",
                                            default = False,
                                            optional = True),
            requirements.BooleanRequirement(name = 'oscp',
                                            description = "Ask OSCP Server if Cert is valid",
                                            default = False,
                                            optional = True),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True)
        ]

    #from https://stackoverflow.com/questions/64436317/how-to-check-ocsp-client-certificate-revocation-using-python-requests-library
    def get_issuer(self, cert):
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        issuers = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.CA_ISSUERS]
        if not issuers:
            raise Exception(f'no issuers entry in AIA')
        return issuers[0].access_location.value

    #from https://stackoverflow.com/questions/64436317/how-to-check-ocsp-client-certificate-revocation-using-python-requests-library
    def get_ocsp_server(self, cert):
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ocsps = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.OCSP]
        if not ocsps:
            raise Exception(f'no ocsp server entry in AIA')
        return ocsps[0].access_location.value

    #from https://stackoverflow.com/questions/64436317/how-to-check-ocsp-client-certificate-revocation-using-python-requests-library
    def get_issuer_cert(self, ca_issuer):
        issuer_response = requests.get(ca_issuer)
        if issuer_response.ok:
            issuerDER = issuer_response.content
            issuerPEM = ssl.DER_cert_to_PEM_cert(issuerDER)
            return x509.load_pem_x509_certificate(issuerPEM.encode('ascii'), default_backend())
        raise Exception(f'fetching issuer cert  failed with response status: {issuer_response.status_code}')

    #from https://stackoverflow.com/questions/64436317/how-to-check-ocsp-client-certificate-revocation-using-python-requests-library
    def get_oscp_request(self, ocsp_server, cert, issuer_cert):
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer_cert, SHA256())
        req = builder.build()
        req_path = base64.b64encode(req.public_bytes(serialization.Encoding.DER))
        return urljoin(ocsp_server + '/', req_path.decode('ascii'))


    def get_ocsp_cert_status(self, ocsp_server, cert, issuer_cert):
        ocsp_resp = requests.get(get_oscp_request(ocsp_server, cert, issuer_cert))
        if ocsp_resp.ok:
            ocsp_decoded = ocsp.load_der_ocsp_response(ocsp_resp.content)
            if ocsp_decoded.response_status == OCSPResponseStatus.SUCCESSFUL:
                return ocsp_decoded.certificate_status
            else:
                raise Exception(f'decoding ocsp response failed: {ocsp_decoded.response_status}')
        raise Exception(f'fetching ocsp cert status failed with response status: {ocsp_resp.status_code}')



    def _generator(self):
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)
        #yara rules to find cert
        rules = yara.compile(sources = {
            'x509' : 'rule x509 {strings: $a = {30 82 ?? ?? 30 82 ?? ??} condition: $a}',
            'pkcs' : 'rule pkcs {strings: $a = {30 82 ?? ?? 02 01 00} condition: $a}',
            })

        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        for task in pslist.PsList.list_processes(context = self.context,
                                                 layer_name = self.config['primary'],
                                                 symbol_table = self.config['nt_symbols'],
                                                 filter_func = filter_func):
            layer_name = task.add_process_layer()
            layer = self.context.layers[layer_name]
            for offset, rule_name, name, value in layer.scan(context = self.context,
                                                             scanner = yarascan.YaraScanner(rules = rules),
                                                             sections = self.get_vad_maps(task)):
                #calculate size of cert
                size = (int((value[2] << 8 & 0xFFFF) + value[3]))+4
                cert="?"                    
                #dump cert    
                try:
                    rawcert = bytes(layer.read(offset=offset, length=size))                                    
                    if self.config['dump']:
                        f = open("CertDump_pid.{0}.{1:#x}.{2}".format(task.UniqueProcessId, offset,rule_name), 'wb')
                        f.write(rawcert)
                        f.close()
                except:
                    cert = "-"                             
                #grab cert information
                try:
                    if((rule_name=="x509")&(cert=="?")):                     
                        #cert_pem=ssl.DER_cert_to_PEM_cert(rawcert)
                        cert_obj=x509.load_der_x509_certificate(rawcert)                    
                        #cert="SN {0} Issuer {1}".format(cert_obj.subject,cert_obj.issuer)
                        subject=str(cert_obj.subject)
                        issuer=str(cert_obj.issuer)
                        not_valid_before = cert_obj.not_valid_before
                        not_valid_after = cert_obj.not_valid_after
                        time_valid = not_valid_after - datetime.datetime.utcnow() > (cert_obj.not_valid_after - cert_obj.not_valid_before)/2
                    else:
                        subject="?"
                        issuer="?"
                        time_valid=False                    
                except:
                    subject="?"
                    issuer="?"
                    time_valid=False
                #oscp test
                try:
                    oscp_status="?"
                    if (rule_name=="x509")&(cert=="?")&(self.config['oscp']):
                        ca_issuer = self.get_issuer(cert_obj)                        
                        issuer_cert = self.get_issuer_cert(ca_issuer)                        
                        ocsp_server = self.get_ocsp_server(cert)                    
                        oscp_status=str(self.get_ocsp_cert_status(ocsp_server, cert, issuer_cert))
                except:                    
                    pass
                    
                yield 0, (format_hints.Hex(offset), task.UniqueProcessId, rule_name, size, subject, issuer, time_valid, oscp_status)

    @staticmethod
    def get_vad_maps(task: interfaces.objects.ObjectInterface) -> Iterable[Tuple[int, int]]:
        """Creates a map of start/end addresses within a virtual address
        descriptor tree.

        Args:
            task: The EPROCESS object of which to traverse the vad tree

        Returns:
            An iterable of tuples containing start and end addresses for each descriptor
        """
        vad_root = task.get_vad_root()
        for vad in vad_root.traverse():
            end = vad.get_end()
            start = vad.get_start()
            yield (start, end - start)

    def run(self):
        return renderers.TreeGrid([('Offset', format_hints.Hex), ('Pid', int), ('Rule', str), ('Size', int),
                                   ('Certificate', str), ('Issuer', str), ('Time_Valid', bool), ('OSCP_valid', str)], self._generator())
