import json
import logging
from iota import Iota, TryteString, TransactionHash, ProposedTransaction, Address, Tag
from typing import List, Dict


class TangleConnector:
    def __init__(self, url='https://nodes.thetangle.org:443', seed="TESTSEED9"):
        self.iri_url = url
        self.iota_api = Iota(url, seed)

    def get_node(self) -> dict:
        """
        Get IRI node info
        """
        try:
            res = self.iota_api.get_node_info()
        except Exception as e:
            logging.warning("Failed to IRI node info for " + self.iri_url, e)
            res = None
        return res

    def get_tips(self) -> dict:
        """
        Get all unreferenced transactions
        """
        try:
            res = self.iota_api.get_tips()
        except Exception as e:
            logging.warning("Failed to get tips", e)
            res = None
        return res

    def get_hashes_from_addr(self, address: Address) -> List[TransactionHash]:
        """
        Get all tx from address
        """
        try:
            response = self.iota_api.find_transactions(addresses=[address])
            hashes = response['hashes']
        except Exception as e:
            logging.warning("Failed to get all tx from address " + address.__str__(), e)
            hashes = None
        return hashes

    def get_trytes_from_hashes(self, hashes: List[TransactionHash]) -> List[TryteString]:
        """
        Get tryte signature fragments from hashes
        """
        try:
            response = self.iota_api.get_trytes(hashes)
            if response['trytes']:
                trytes = [tryte[0:2187] for tryte in response['trytes']]
        except Exception:
            logging.warning("Failed to get all signature fragments")
            trytes = None
        return trytes

    def get_all_trytes_from_address(self, address: Address) -> Dict[TransactionHash, TryteString]:
        """
        Get all trytes from address
        """
        hashes = self.get_hashes_from_addr(address)
        trytes = self.get_trytes_from_hashes(hashes)
        if hashes and trytes:
            result = dict(zip(hashes, trytes))
        else:
            result = None
        return result

    @staticmethod
    def get_json_from_tryte(tryte: TryteString) -> dict:
        try:
            str_from_tryte = tryte.as_string()
            dict_from_tryte = json.loads(str_from_tryte)
        except Exception as e:
            logging.error("Failed to convet trytes to JSON", e)
            dict_from_tryte = None
        return dict_from_tryte

    def send_msg_to_addr(self, address: Address, msg: str, tag: str) -> dict:
        """
        Sends msg on Tangle to address with a tag
        """
        try:
            response = self.iota_api.send_transfer(
                depth=5,
                transfers=[ProposedTransaction(address=address, value=0,
                                               tag=Tag(tag), message=TryteString.from_string(msg))]
            )
        except Exception as e:
            logging.warning("Message '" + msg + "' has failed to be stored in " + address.__str__(),e)
            response = None
        return response
