import logging
import datetime
import time
import censys.ipv4
from pymongo import MongoClient, ReturnDocument

# Nice - using spaces instead of tabs!

FIELDNAME_HASH = "SHA_1"
FIELDNAME_CERT_FRIENDLY_NAME = "friendly_name"
FIELDNAME_SOURCE = "source"
FIELDNAME_APT = "APT"
FIELDNAME_DATE_CERT_WAS_LAST_OBSERVED = "date_last_observed_on_any_ip"  # maybe drop the on_any_ip
FIELDNAME_PREVIOUSLY_OBSERVED_IPS = "all_observed_ips"
FIELDNAME_IP_ADDR = "IP"
FIELDNAME_COUNTRY_CODE = "country_code"
FIELDNAME_COUNTRY_NAME = "country_name"
FIELDNAME_PORTS_PROTOCOLS = "ports_and_protocols"
FIELDNAME_DATE_SEEN = "date_seen"

EXPORT_FILE = "monitored_certificates.txt"
IMPORT_FILE = "import_test.csv"

logging.basicConfig(filename='cert_monitoring.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

IPv4_API_URL = "https://www.censys.io/api/v1/search/ipv4"
API_UID = ""
API_KEY = ""

TODAY = datetime.date.today().isoformat()

FIELDS_TO_RETURN_FROM_CENSYS = ["443.https.tls.certificate.parsed.fingerprint_sha1",
                                "ip",
                                "location.country_code",
                                "location.country",
                                "protocols"]
CENSYS_SEARCH_ENGINE = censys.ipv4.CensysIPv4(API_UID, API_KEY)


def main():

    logging.info("******** CERT MONITOR IS STARTING! **********")

    cert_db = SSL_Certificate_Database()

    cert_db.import_new_certs_from_csv(csv_path=IMPORT_FILE)

    logging.info("There are currently %s certificates in the database" % cert_db.count())

    for sha1 in cert_db.all_sha1s():
        previously_observed_ips_for_sha1 = cert_db.previously_observed_ips_for_cert(sha1)

        logging.info("Querying Censys for any IPs utilizing certificate: %s" % sha1)

        for search_result in CENSYS_SEARCH_ENGINE.search(sha1, FIELDS_TO_RETURN_FROM_CENSYS):

            if not previously_observed_ips_for_sha1:
                cert_db.add_ip_to_cert(sha1,
                                       search_result['ip'],
                                       search_result['location.country_code'],
                                       search_result['location.country'],
                                       search_result['protocols'])

            elif search_result['ip'] in previously_observed_ips_for_sha1:
                    logging.info("Censys observed IP %s utilizing cert %s. This is a previously known association." % (search_result['ip'], sha1))
                    cert_db.update_the_date_an_ip_was_last_seen(sha1, search_result['ip'])

            else:
                logging.info("Censys observed IP %s utilizing cert %s. This is a new association." % (search_result['ip'],
                                                                                                      sha1))

                cert_db.add_ip_to_cert(sha1,
                                       search_result['ip'],
                                       search_result['location.country_code'],
                                       search_result['location.country'],
                                       search_result['protocols'])

        time.sleep(5)  # Required so I don't exceed my API quota #lol good example of a needed comment

    logging.info("Total number of IPs ever observed by this script: %s" % len(cert_db.all_observed_ips()))

    all_tracked_APTs = cert_db.all_tracked_APTs()

    logging.info("Certificates associated with %s APTs are being monitored" % len(all_tracked_APTs))

    for apt in all_tracked_APTs:
        certs_associated_with_apt = cert_db.certs_associated_with_apt(apt)
        logging.info("We\'re monitoring %s certs associated with APT %s: %s" % (len(certs_associated_with_apt),
                                                                                apt,
                                                                                certs_associated_with_apt))

    # cert_db.export_all_certs_to_file()    #??

    logging.info("******** CERT MONITOR IS FINISHED! **********")

    return


class CertificateObject(object):
    def __init__(self, sha_hash=None, friendly_name=None, source=None, apt=None, date_last_observed=None,
                 observed_ips={}):

        self.attributes = {FIELDNAME_HASH: sha_hash,
                           FIELDNAME_CERT_FRIENDLY_NAME: friendly_name,
                           FIELDNAME_SOURCE: source,
                           FIELDNAME_APT: apt,
                           FIELDNAME_DATE_CERT_WAS_LAST_OBSERVED: date_last_observed,
                           FIELDNAME_PREVIOUSLY_OBSERVED_IPS: observed_ips,
                           }

        return


class SSL_Certificate_Database(object):
    def __init__(self):

        self.mongo = MongoClient()
        self.ssl_certificate_monitoring_db = self.mongo.ssl_certificate_monitoring_db
        self.ssl_cert_collection = self.ssl_certificate_monitoring_db.monitored_certs_collection

        return

    def is_cert_in_db(self, cert_sha256_to_check):
        cert_in_db = self.ssl_cert_collection.find_one({FIELDNAME_HASH: cert_sha256_to_check})
        if cert_in_db:
            logging.debug("Cert %s is in collection" % cert_sha256_to_check)
            return True
        else:
            logging.debug("Cert %s is not in collection" % cert_sha256_to_check)
            return False

    def add_new_cert_object_to_collection(self, cert_object):
        cert_hash = cert_object.attributes[FIELDNAME_HASH]
        cert_is_in_collection = self.is_cert_in_db(cert_hash)
        if cert_is_in_collection:
            logging.info("Cert %s is already in the collection. Will not add it." % cert_hash)
            return False
        else:
            id_of_inserted_cert = self.ssl_cert_collection.insert_one(cert_object.attributes).inserted_id
            logging.info("Added cert %s to collection. ID: %s. Observed IPs: %s" % (cert_object.attributes[FIELDNAME_HASH],
                                                                                    id_of_inserted_cert,
                                                                                    cert_object.attributes[FIELDNAME_PREVIOUSLY_OBSERVED_IPS]))
            return True

    def all_cert_objects(self):
        list_of_monitored_certs = []
        for cert in self.ssl_cert_collection.find():
            list_of_monitored_certs.append(cert)
        return list_of_monitored_certs

    def all_sha1s(self):
        list_of_monitored_certs_objects = self.all_cert_objects()
        monitored_certs_by_hash = [cert_object[FIELDNAME_HASH] for cert_object in list_of_monitored_certs_objects]
        return monitored_certs_by_hash

    def previously_observed_ips_for_cert(self, cert_hash):
        cert_object = self.get_cert_object(cert_hash)
        if cert_object:
            if cert_object[FIELDNAME_PREVIOUSLY_OBSERVED_IPS]:
                # Must replace "-" with "." in each IP address b/c Mongo doesn't allow keys containing "."
                return [observed_ips_and_attributes.replace("-", ".") for observed_ips_and_attributes in cert_object[FIELDNAME_PREVIOUSLY_OBSERVED_IPS]]

            else:
                logging.info("Cert %s has not been previously observed on any IPs" % cert_hash)
                return []
        else:
            logging.error("Error: cert %s is not in the database??" % cert_hash)
            return []

    def update_the_date_an_ip_was_last_seen(self, sha1, ip_to_update):

        mongo_id_of_cert_record_in_db = self.get_mongo_id_for_cert(sha1)

        previously_observed_ips = self.previously_observed_ips_for_cert(sha1)

        if ip_to_update in previously_observed_ips:
            cert_object = self.get_cert_object(sha1)
            ips_and_attributes = cert_object[FIELDNAME_PREVIOUSLY_OBSERVED_IPS]
            # Must replace "." with "-" in each IP address b/c Mongo doesn't allow keys containing "."
            ip_and_attributes_to_update = ips_and_attributes[str(ip_to_update.replace('.', '-'))]
            ip_and_attributes_to_update[FIELDNAME_DATE_SEEN] = TODAY
            # Must replace "." with "-" in each IP address b/c Mongo doesn't allow keys containing "."
            ips_and_attributes[str(ip_to_update.replace('.', '-'))] = ip_and_attributes_to_update
            result = self.ssl_cert_collection.find_one_and_update({'_id': mongo_id_of_cert_record_in_db},
                                                                  {'$set': {FIELDNAME_DATE_CERT_WAS_LAST_OBSERVED: TODAY,
                                                                            FIELDNAME_PREVIOUSLY_OBSERVED_IPS: ips_and_attributes}},
                                                                  return_document=ReturnDocument.AFTER)
            if result:
                logging.info("Updated the last observed data for cert %s associated with IP %s" % (sha1, ip_to_update))
                return True
            else:
                logging.error("Failed to update the last observed date for cert %s associated with IP %s" % (sha1, ip_to_update))
                return False

        else:
            logging.error("IP %s is not currently associated with cert %s" % (ip_to_update, sha1))
            return False

    def add_ip_to_cert(self, sha1, ip, country_code, country_name, ports_protocols):

        ip_attributes = {FIELDNAME_IP_ADDR: ip,
                         FIELDNAME_COUNTRY_CODE: country_code,
                         FIELDNAME_COUNTRY_NAME: country_name,
                         FIELDNAME_PORTS_PROTOCOLS: ports_protocols,
                         FIELDNAME_DATE_SEEN: TODAY}


        cert_object = self.get_cert_object(sha1)
        cert_mongo_id = cert_object['_id']

        previously_observed_ips = self.previously_observed_ips_for_cert(sha1)

        if ip in previously_observed_ips:
            logging.error("IP %s is already associated with cert %s" % (ip, sha1))
            return False
        else:
            cert_object = self.get_cert_object(sha1)
            ips_and_attributes = cert_object[FIELDNAME_PREVIOUSLY_OBSERVED_IPS]

            # Must replace "." with "-" in each IP address b/c Mongo doesn't allow keys containing "."
            ips_and_attributes[str(ip.replace('.', '-'))] = ip_attributes
            result = self.ssl_cert_collection.find_one_and_update({'_id': cert_mongo_id},
                                                                  {'$set': {FIELDNAME_DATE_CERT_WAS_LAST_OBSERVED: TODAY,
                                                                            FIELDNAME_PREVIOUSLY_OBSERVED_IPS: ips_and_attributes}},
                                                                   return_document=ReturnDocument.AFTER)
            if result:
                logging.info("Associated IP %s with cert %s in the database" % (ip, sha1))
                return True
            else:
                logging.error("Failed to associated IP %s with cert %s in the database" % (ip, sha1))
                return False

    def get_cert_object(self, cert_hash):
        return self.ssl_cert_collection.find_one({FIELDNAME_HASH: cert_hash})

    def get_mongo_id_for_cert(self, cert_hash):
        try:
            mongo_id_of_cert = self.get_cert_object(cert_hash)['_id']
            return mongo_id_of_cert
        except Exception as not_found_error:
            logging.error("Error: issue obtaining mongo id for cert %s. Msg: %s" % (cert_hash, not_found_error))
            return None

    def import_new_certs_from_csv(self, csv_path):
        """
        Import a list of certs from a csv
        :param csv_path: Path to file to import from. CSV format should be this: sha1_hash,apt
        :return: 
        """
        with open(csv_path, 'r') as csv_to_import:
            logging.info("Importing certs from file: %s" % csv_path)

            rows_in_csv = csv_to_import.readlines()

            for row_in_csv in rows_in_csv:
                sha_hash_of_new_cert = row_in_csv.split(",")[0]
                apt_attribution_of_new_cert = row_in_csv.split(",")[1].strip('\n')

                new_cert = CertificateObject(sha_hash=sha_hash_of_new_cert,
                                             apt=apt_attribution_of_new_cert,
                                             observed_ips={}
                                             )

                self.add_new_cert_object_to_collection(new_cert)

    def wipe_cert_collection(self):
        """
        DANGER! This function will wipe the database
        :return: 
        """
        self.mongo.drop_database(self.ssl_certificate_monitoring_db)
        return

    def export_all_certs_to_file(self):
        all_certs = self.all_cert_objects()
        with open(EXPORT_FILE, 'w') as export_file:
            for cert in all_certs:
                export_file.write(str(cert))
                export_file.write('\n')
        return

    def all_observed_ips(self):
        all_certs = self.all_cert_objects()
        all_observed_ips_on_all_certs = []
        for cert in all_certs:
            if self.previously_observed_ips_for_cert(cert[FIELDNAME_HASH]):
                for observed_ip in self.previously_observed_ips_for_cert(cert[FIELDNAME_HASH]):
                    if observed_ip not in all_observed_ips_on_all_certs:
                        all_observed_ips_on_all_certs.append(observed_ip)
        return all_observed_ips_on_all_certs

    def all_tracked_APTs(self):
        all_certs = self.all_cert_objects()
        all_apts = []
        [all_apts.append(cert[FIELDNAME_APT]) for cert in all_certs if not all_apts.__contains__(cert[FIELDNAME_APT])]
        logging.debug("All APTs: %s" % all_apts)
        return all_apts

    def certs_associated_with_apt(self, apt):
        """
        Get a list of certificates associated with a specified APT
        :param apt: APT for which to retrieve associated certs
        :return: 
        """
        results = self.ssl_cert_collection.find({FIELDNAME_APT: apt})
        all_certs_for_apt = []
        for cert in results:
            all_certs_for_apt.append(cert[FIELDNAME_HASH])
        return all_certs_for_apt

    def count(self):
        """
        Get a count of the number of certificates being tracked
        :return: 
        """
        cert_count = len(self.all_sha1s())
        return cert_count

if __name__ == "__main__":
    main()