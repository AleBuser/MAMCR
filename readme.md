# MAMCR Python library
------
Added Timestamps to MAML
Added Commit-Reveal functionalities to MAML for delayed publication of information

### Usage

```python
import random
import string
from iota import Address
from ciphers import Ed25519Cipher
from mam_lite import MAML_Ed25519

addr = Address(''.join(random.choices(string.ascii_uppercase + '9', k=81)))

password = "SAFE_PASSWORD"

CR = MAMCR(addr,password)

DataToTransfer = {
    "field1" : "Something1",
    "field2" : "Something2",
    "field3" : "Something3",
}

CR.Commit(DataToTransfer)

CR.Reveal()


while True:

    res = CR.CheckAndGetData()

    if res != None:
        print(res)
    else:
        break;



```




