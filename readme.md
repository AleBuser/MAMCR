# MAMCR Python library
------
Commit Reveal over MAML, allows to delay publication of information while mainitaning generation time athenticity

### Usage

```python
import random
import string
import time
from iota import Address
from ciphers import Ed25519Cipher
from mam_lite import MAML_Ed25519
from writer import MAM_Writer
from reader import MAM_Reader
from MAMCR import MAMCR

addr = Address(''.join(random.choices(string.ascii_uppercase + '9', k=81)))

password = "SAFE_PASSWORD"

CR = MAMCR(addr,password)

DataToTransfer = {
    "field1" : "Something1",
    "field2" : "Something2",
    "field3" : "Something3",
}

CR.Commit(DataToTransfer)

time.sleep(15)

CR.Reveal()


while True:

    res = CR.CheckAndGetData()

    if res != None:
        print(res)
    else:
        break;



```




