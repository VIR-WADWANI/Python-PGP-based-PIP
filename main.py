from py_abac import PDP, Policy, Request
from py_abac.storage.memory import MemoryStorage
from py_abac import EvaluationAlgorithm

from PGPPIP import PGPPIP

#Creating storage for policies
storage = MemoryStorage() 

#Creating a policy for testing
policy = {
    "uid" : "1",
    "description" : "Allow employees only",
    "effect" : "allow",
    "rules" : {
        "subject" : {
            "role" : {
                "condition" : "Equals",
                "value" : "employee"
            }
        }
    },
    "targets" : {},
    "priority" : 0
}

storage.add(Policy.from_json(policy))

#Creating the PIP to be used, that uses the PGPPIP class
pip = PGPPIP(gpg_home="/Users/virwadwani/gnupgHome/gnupg_test", public_key_path="SoA_public_pem.pem")

#Creating the pdp - sets the attribute_providers list to only contain the pip we created
pdp = PDP(storage, EvaluationAlgorithm.HIGHEST_PRIORITY, [pip])

#The request in json to be used for testing
req = {
    "subject" : {
        "id" : "employee1",
        "attributes" : {
            "fingerprint" : "D031FE189631DB147B774C24B5699E4D4496B14A"
        }
        
    },
    "resource" : {"id" : "resource1"},
    "action" : {"id" : "read"},
    "context" : {}
}

request = Request.from_json(req)

#Doing the pdp evaluation
#decision = pdp.is_allowed(request)
#print("Decision:", decision)

# Fake request context for testing
class DummyContext:
    def get_attribute_value(self, entity, path):
        print(f"[DummyContext] get_attribute_value called for {path}")
        return pip.get_attribute(path)

ctx = DummyContext()
print(ctx.get_attribute_value("subject", "$.role"))