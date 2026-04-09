
# Main file for running PDP and policies

import time
from py_abac import PDP, Policy, Request
from py_abac.storage.memory import MemoryStorage
from py_abac import EvaluationAlgorithm

from PGPPIP import PGPPIP

# Creating storage for policies to be used by PDP
storage = MemoryStorage() 

# Creating a policy for testing 
policy = {
    "uid" : "1",
    "description" : "Employees from admin department can access resource",
    "effect" : "allow",
    "rules" : {
        "subject" : #{"$.department" : {"condition" : "Equals", "value" : "admin"}}
        {"$.role" : {"condition" : "Equals", "value" : "employee"}}
        #{"$.location" : {"condition" : "Equals", "value" : "Dubai"}}
    },
    "targets" : {},
    "priority" : 0
}

storage.add(Policy.from_json(policy)) 

# Creating the PIP to be used, that uses the PGPPIP class
pip = PGPPIP(gpg_home="/Users/virwadwani/gnupgHome/gnupg_test", public_key_path="SoA_public_pem.pem",
            trusted_signers=["9458FC85A299E808","F08FFDE500C0D7DD"])

# Creating the PDP - sets the attribute_providers list to only contain the PIP we created
pdp = PDP(storage, EvaluationAlgorithm.HIGHEST_PRIORITY, providers=[pip])

# The request in json to be used for testing holding only the certificate fingerprint
req = {
    "subject" : {
        "id" : "employee1",
        "attributes" : {
            "fingerprint" : "DE4A1E6068D18BFF0D5444539E66C93A3F83402B"
        }
    },
    "resource" : {"id" : "resource1"},
    "action" : {"id" : "read"},
    "context" : {}
}

request = Request.from_json(req)


# Doing the pdp evaluation - for checking time of completion
'''times = []
for i in range(10):
    start = time.time()
    decision = pdp.is_allowed(request)
    end = time.time()
    times.append(end - start)
#print("Decision:", decision)
print("avg time:", sum(times)/len(times))
'''
# Doing PDP evaluation
decision = pdp.is_allowed(request)
print("Decision:", decision)
