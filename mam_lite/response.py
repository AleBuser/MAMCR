import json
from mam_lite import Message


class Response:

    def __init__(self, addr: str, next_addr: str, msg: Message, is_valid, is_trusted):
        self.addr = addr
        self.next_addr = next_addr
        self.msg = msg
        self.is_valid = is_valid
        self.is_trusted = is_trusted

    def __str__(self):
        copy_res_dict = self.__dict__.copy()
        copy_res_dict['msg'] = self.msg.__dict__
        return json.dumps(copy_res_dict)