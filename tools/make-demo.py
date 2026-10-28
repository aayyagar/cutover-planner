"""Builds the fictional Contoso demo tenant for the Cutover Planner (deterministic)."""
import json, random, os
from collections import Counter
random.seed(4242)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXO="00000002-0000-0ff1-ce00-000000000000"; SPO="00000003-0000-0ff1-ce00-000000000000"; TEAMS="cc15fd57-2c6c-4117-a88c-83b1d56b4bbe"
ARM="797f4846-ba00-4fd7-ba43-dac1f8f63013"; GRAPH="00000003-0000-0000-c000-000000000000"; CRM="9a1b2c3d-0000-4000-8000-0000000c0001"
RES={EXO:"Office 365 Exchange Online",SPO:"Office 365 SharePoint Online",TEAMS:"Microsoft Teams Services",ARM:"Windows Azure Service Management API",GRAPH:"Microsoft Graph",CRM:"Contoso CRM"}
first=["alex","sam","jordan","taylor","priya","lena","dan","mark","nina","omar","li","sofia","ken","maria","raj","emma","yusuf","chloe","ivan","ana","tom","zara","leo","mia","noah","ella","ravi","hana","oscar","ines","femi","aiko","bruno","carla","dev","eva","farah","gus","hugo","iris"]
last=["shah","ortiz","okafor","jensen","kim","patel","garcia","nguyen","silva","cohen","berg","rossi","khan","haddad","mori","novak","adeyemi","larsen","dubois","costa"]
depts=[("Sales",90),("Finance",45),("Engineering",70),("HR",25),("Operations",60),("Retail Stores",80),("IT",30),("Legal",20)]
users=[]; i=0
for d,n in depts:
    for k in range(n):
        u={"id":f"u-{i:04d}","upn":f"{first[i%40]}.{last[(i*7)%20]}{i}@contoso.com","name":f"{first[i%40].title()} {last[(i*7)%20].title()}","department":d,"type":"member","admin":False}
        users.append(u); i+=1
for u in users[:]:
    if u["department"]=="IT" and int(u["id"][2:])%3==0: u["admin"]=True
admins=[u for u in users if u["admin"]]
guests=[{"id":f"g-{k:03d}","upn":f"{first[k]}_partner{k}#EXT#@contoso.onmicrosoft.com","name":f"{first[k].title()} (partner)","department":"","type":"guest","admin":False} for k in range(18)]
svc={"id":"u-svc1","upn":"svc-reporting@contoso.com","name":"svc-reporting","department":"IT","type":"member","admin":False}
bg=[{"id":"u-bg01","upn":"breakglass01@contoso.onmicrosoft.com","name":"Break-glass 01","department":"","type":"member","admin":True},
    {"id":"u-bg02","upn":"breakglass02@contoso.onmicrosoft.com","name":"Break-glass 02","department":"","type":"member","admin":True}]
everyone=users+guests+[svc]+bg
regs=[]; signins=Counter()
def reg(u, methods): regs.append({"id":u["id"],"userPrincipalName":u["upn"],"userDisplayName":u["name"],"userType":u["type"],"isAdmin":u["admin"],"methodsRegistered":methods})
def add(u,res,client,os_,trust="",managed=False,proto="none",methods=("Password",),tp=None,n=1,interactive=True):
    signins[(u["id"],res,client,os_,trust,managed,proto,tuple(methods),json.dumps(tp) if tp else "",interactive)]+=n
for u in users:
    d=u["department"]
    if d=="Engineering" or d=="IT": dev=random.choices(["win11","mac14","linux"],[55,25,20])[0]
    elif d=="Retail Stores": dev=random.choices(["kiosk","win10"],[75,25])[0]
    else: dev=random.choices(["win11","win10","mac14","mac12","win81"],[62,22,10,4,2])[0]
    mob=random.choices(["iOS 18.1","iOS 16.7","Android 15","Android 13",None],[48,6,28,6,12])[0]
    if d=="Retail Stores": mob=random.choices(["Android 14","Android 13",None],[40,10,50])[0]
    # registered methods
    m=["mobilePhone"]
    r=random.random()
    if u["admin"]: m+= ["microsoftAuthenticatorPush"] + (["fido2SecurityKey"] if r<0.6 else []) + (["passKeyDeviceBoundAuthenticator"] if r<0.3 else [])
    elif d in("Engineering","IT"): m+= ["microsoftAuthenticatorPush"] + (["windowsHelloForBusiness"] if dev=="win11" and r<0.75 else []) + (["passKeyDeviceBoundAuthenticator"] if r<0.35 else []) + (["fido2SecurityKey"] if dev=="linux" and r<0.4 else [])
    elif d=="Retail Stores": m+= (["microsoftAuthenticatorPush"] if r<0.4 else [])
    else:
        m+= ["microsoftAuthenticatorPush"] if r<0.9 else ["softwareOneTimePasscode"]
        if dev in("win11","win10") and random.random()<0.45: m.append("windowsHelloForBusiness")
        if random.random()<0.22: m.append("passKeySynced")
        if dev=="mac14" and random.random()<0.4: m.append("macOsSecureEnclaveKey")
    reg(u,m)
    pr_methods=[x for x in m if x in("fido2SecurityKey","windowsHelloForBusiness","passKeyDeviceBoundAuthenticator","passKeySynced","macOsSecureEnclaveKey")]
    used = ("Windows Hello for Business",) if "windowsHelloForBusiness" in pr_methods and random.random()<0.7 else (("Passkey (device-bound)",) if pr_methods and random.random()<0.3 else ("Password","Microsoft Authenticator (push)"))
    osmap={"win11":("Windows 11","Azure AD joined",True),"win10":("Windows 10","Hybrid Azure AD joined",True),"mac14":("MacOs 14.5","",random.random()<0.7),"mac12":("MacOs 12.7","",False),"win81":("Windows 8.1","",False),"linux":("Linux","",False),"kiosk":("Windows 10","Azure AD joined",True)}
    os_,trust,managed=osmap[dev]
    if dev=="win10" and random.random()<0.15: trust=""          # unregistered personal PC
    for res,w in [(EXO,8),(SPO,5),(TEAMS,9),(GRAPH,3),(CRM,2)]:
        add(u,res,"Browser",os_,trust,managed,methods=used,n=w*random.randint(1,3))
        if res in (EXO,SPO,TEAMS) and dev not in("linux",):
            if os_.startswith("Windows") and trust: tp={"signInSessionStatus":"bound","signInSessionStatusCode":0} if random.random()<0.93 else {"signInSessionStatus":"unbound","signInSessionStatusCode":1008}
            elif os_.startswith("Windows"): tp={"signInSessionStatus":"unbound","signInSessionStatusCode":1002}
            elif os_.startswith("MacOs") and managed: tp={"signInSessionStatus":"bound","signInSessionStatusCode":0}
            else: tp={"signInSessionStatus":"unbound","signInSessionStatusCode":1006 if dev in("mac12","win81") else 1002}
            add(u,res,"Mobile Apps and Desktop clients",os_,trust,managed,methods=used,tp=tp,n=w*random.randint(3,8),interactive=False)
        if mob and res in (EXO,TEAMS):
            mtp={"signInSessionStatus":"bound","signInSessionStatusCode":0} if mob.startswith("iOS 18") and random.random()<0.6 else None
            add(u,res,"Mobile Apps and Desktop clients",mob,"",bool(mtp),methods=used,tp=mtp,n=w*random.randint(1,4),interactive=False)
    if d in("Engineering","IT"):
        add(u,ARM,"Browser",os_,trust,managed,methods=used,n=random.randint(3,12))
        if dev=="linux": add(u,ARM,"Mobile Apps and Desktop clients","Linux",proto="deviceCode",methods=used,n=random.randint(2,10))
    if random.random()<0.03 and d not in("Engineering","IT"): add(u,EXO,"Exchange ActiveSync",mob or "iOS 16.7",methods=("Password",),n=random.randint(10,60),interactive=False)
for u in admins: add(u,ARM,"Browser","Windows 11","Azure AD joined",True,methods=("FIDO2 security key",) if random.random()<0.5 else ("Password","Microsoft Authenticator (push)"),n=15)
reg(svc,["mobilePhone"]); add(svc,EXO,"Mobile Apps and Desktop clients","",proto="ropc",methods=("Password",),n=720,interactive=False); add(svc,SPO,"Mobile Apps and Desktop clients","",proto="ropc",methods=("Password",),n=300,interactive=False)
for b in bg: reg(b,["fido2SecurityKey"]); add(b,ARM,"Browser","Windows 11","Azure AD joined",True,methods=("FIDO2 security key",),n=2)
for g in guests:
    reg(g,["microsoftAuthenticatorPush"])
    add(g,TEAMS,"Browser",random.choice(["Windows 11","MacOs 14.5"]),methods=("Password","Microsoft Authenticator (push)"),n=random.randint(3,20))
scanner={"id":"u-0199","upn":users[199]["upn"]}
out=[]
for k,n in signins.items():
    uid,res,client,os_,trust,managed,proto,methods,tp,inter=k
    s={"userId":uid,"resourceId":res,"resourceDisplayName":RES[res],"clientAppUsed":client,"deviceDetail":{"operatingSystem":os_,"trustType":trust,"isManaged":managed},
       "authenticationProtocol":proto,"authMethods":list(methods),"isInteractive":inter,"count":n}
    if tp: s["tokenProtectionStatusDetails"]=json.loads(tp)
    out.append(s)
directory={"users":{u["id"]:{"upn":u["upn"],"displayName":u["name"],"department":u["department"],"userType":u["type"]} for u in everyone},
  "personaGroups":{"ITPro":{"displayName":"Persona - IT pros and DevOps","members":[u["id"] for u in users if u["department"] in("IT","Engineering") and not u["admin"] and (u["department"]=="IT" or int(u["id"][2:])%2==0)]},
                   "Frontline":{"displayName":"Persona - Frontline","members":[u["id"] for u in users if u["department"]=="Retail Stores"]},
                   "Regulated":{"displayName":"Persona - Highly regulated (Treasury)","members":[u["id"] for u in users if u["department"]=="Finance"][:12]}},
  "breakGlass":[b["id"] for b in bg]}
json.dump({"label":"Contoso (demo tenant)","now":"2026-10-28T12:00:00Z","days":30,"registrations":regs,"directory":directory,"signIns":out},
          open(os.path.join(ROOT,"demo/sample-tenant.json"),"w"),separators=(",",":"))
print("users",len(everyone),"regs",len(regs),"shapes",len(out),"signins",sum(signins.values()))
