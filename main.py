import time
from py_abac import PDP, Policy, Request
from py_abac.storage.memory import MemoryStorage
from py_abac import EvaluationAlgorithm

from PGPPIP import PGPPIP

#Creating storage for policies
storage = MemoryStorage() 

#Creating a policy for testing
policy = {
    "uid" : "1",
    "description" : "Employees from admin department can access resource",
    "effect" : "allow",
    "rules" : {
        "subject" : #{"$.department" : {"condition" : "Equals", "value" : "admin"}}
        {"$.role" : {"condition" : "Equals", "value" : "employee"}}
    },
    "targets" : {},
    "priority" : 0
}

storage.add(Policy.from_json(policy))

#Creating the PIP to be used, that uses the PGPPIP class
pip = PGPPIP(gpg_home="/Users/virwadwani/gnupgHome/gnupg_test", public_key_path="SoA_public_pem.pem",
            trusted_signers=["9458FC85A299E808","F08FFDE500C0D7DD"])

#Creating the pdp - sets the attribute_providers list to only contain the pip we created
pdp = PDP(storage, EvaluationAlgorithm.HIGHEST_PRIORITY, providers=[pip])

#The request in json to be used for testing
req = {
    "subject" : {
        "id" : "employee1",
        "attributes" : {
            "fingerprint" : "729175D76FDBEB1A3D5E024BE2FCFAA28898484C"
        }
    },
    "resource" : {"id" : "resource1"},
    "action" : {"id" : "read"},
    "context" : {}
}

request = Request.from_json(req)


#Doing the pdp evaluation - time
'''times = []
for i in range(10):
    start = time.time()
    decision = pdp.is_allowed(request)
    end = time.time()
    times.append(end - start)
#print("Decision:", decision)
print("avg time:", sum(times)/len(times))
'''
#Doing PDP evaluation
decision = pdp.is_allowed(request)
print("Decision:", decision)

# Fake request context for testing
'''class DummyContext:
    def get_attribute_value(self, entity, path):
        print(f"[DummyContext] get_attribute_value called for {path}")
        return pip.get_attribute(path)

ctx = DummyContext()
print(ctx.get_attribute_value("subject", "$.role"))'''